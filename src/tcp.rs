use bitflags::bitflags;
use std::collections::{BTreeMap, VecDeque};
use std::{io, time};
use etherparse::{Ipv4Header, TcpHeader, Ipv4HeaderSlice, TcpHeaderSlice, IpTrafficClass};
use tun_tap::Iface;

//Spec: RFC 793: https://datatracker.ietf.org/doc/html/rfc793

bitflags! {
	pub(crate) struct Available: u8 {
		const READ = 0b00000001;
		const WRITE = 0b00000010;
	}
}

#[derive(Debug)]
enum State {
	//Closed,
	//Listen,
	SynRecvd,
	Estab,
	FinWait1,
	FinWait2,
	TimeWait,
}

impl State {
	fn is_synchronized(&self) -> bool {
		match *self {
			State::SynRecvd => false,
			State::Estab | State::FinWait1 | State::FinWait2 | State::TimeWait => true,
		}
	}
}

struct SendSequenceSpace {
	una: u32,
	nxt: u32,
	wnd: u16,
	up: bool,
	wl1: usize,
	wl2: usize,
	iss: u32,
}

struct RecvSequenceSpace {
	nxt: u32,
	wnd: u16,
	up: bool,
	irs: u32,
}

struct Timers {
	send_times: BTreeMap<u32, time::Instant>,
	srtt: f64,
}

pub struct Connection {
	state: State,
	send: SendSequenceSpace,
	recv: RecvSequenceSpace,
	ip: Ipv4Header,
	tcp: TcpHeader,
	timers: Timers,
	pub(crate) incoming: VecDeque<u8>,
	pub(crate) unacked: VecDeque<u8>,
	pub(crate) closed: bool,
	closed_at: Option<u32>,
}

impl Connection {
	pub(crate) fn is_rcv_closed(&self) -> bool {
		if let State::TimeWait = self.state {
			true
		} else {
			false
		}
	}

	fn availability(&self) -> Available {
		let mut a = Available::empty();
		if self.is_rcv_closed() || !self.incoming.is_empty() {
			a |= Available::READ;
		}

		a
	}
}

impl Connection {
	pub fn accept<'a>(nic: &mut Iface, iph: Ipv4HeaderSlice<'a>, tcph: TcpHeaderSlice<'a>, data:
	&'a [u8], ) -> io::Result<Option<Self>> {
		let buf = [0u8; 1504];
		if !tcph.syn() {
			return Ok(None);
		}

		let iss = 0;
		let wnd = 1024;
		let mut c = Connection {
			timers: Timers {
				send_times: Default::default(),
				srtt: time::Duration::from_secs(1 * 60).as_secs_f64(),
			},
			state: State::SynRecvd,
			send: SendSequenceSpace {
				iss,
				una: iss,
				nxt: iss,
				wnd: wnd,
				up: false,
				wl1: 0,
				wl2: 0,
			},
			recv: RecvSequenceSpace {
				irs: tcph.sequence_number(),
				nxt: tcph.sequence_number() + 1,
				wnd: tcph.window_size(),
				up: false,
			},
			tcp: TcpHeader::new(
				tcph.destination_port(),
				tcph.source_port(), iss, wnd),
			ip: Ipv4Header::new(
				0, 64, IpTrafficClass::Tcp,
				[
					iph.destination()[0],
					iph.destination()[1],
					iph.destination()[2],
					iph.destination()[3],
				],
				[
					iph.source()[0],
					iph.source()[1],
					iph.source()[2],
					iph.source()[3],
				],
			),
			incoming: Default::default(),
			unacked: Default::default(),
			closed: false,
			closed_at: None,
		};

		c.tcp.syn = true;
		c.tcp.ack = true;
		c.write(nic, c.send.nxt, 0)?;
		Ok(Some(c))
	}

	fn write(&mut self, nic: &mut Iface, seq: u32, mut limit: usize) -> io::Result<usize> {
		let mut buf = [0u8; 1500];
		self.tcp.sequence_number = seq;
		self.tcp.acknowledgment_number = self.recv.nxt;

		println!("write(ack: {}, seq: {}, limit: {}) syn {:?} fin {:?}",
			self.recv.nxt - self.recv.irs, seq, limit, self.tcp.syn, self.tcp.fin,
		);

		let mut offset = seq.wrapping_sub(self.send.una) as usize;
		if let Some(closed_at) = self.closed_at{
			if seq == closed_at.wrapping_add(1) {
				offset = 0;
				limit = 0;
			}
		}
		println!("using offset {} base {} in {:?}", offset, self.send.una, self.unacked.as_slices
		());
		let (mut h, mut t) = self.unacked.as_slices();
		if h.len() >= offset {
			h = &h[offset..];
		} else {
			let skipped = h.len();
			h = &[];
			t = &t[(offset - skipped)..];
		}

		let max_data = std::cmp::min(limit, h.len() + t.len());
		let size = std::cmp::min(buf.len(), self.tcp.header_len() as usize + self.ip.header_len()
								 as usize + max_data,);
		self.ip.set_payload_len(size - self.ip.header_len() as usize);

		use io::Write;
		let buf_len = buf.len();
		let mut unwritten = &mut buf[..];

		self.ip.write(&mut unwritten);
		let ip_header_ends_at = buf_len - unwritten.len();

		unwritten = &mut unwritten[self.tcp.header_len() as usize..];
		let tcp_header_ends_at = buf_len - unwritten.len();

		let payload_bytes = {
			let mut written = 0;
			let mut limit = max_data;

			let p1l = std::cmp::min(limit, h.len());
			written += unwritten.write(&h[..p1l])?;
			limit -= written;

			let p2l = std::cmp::min(limit, t.len());
			written += unwritten.write(&t[..p2l])?;
			written
		};

		let payload_ends_at = buf_len - unwritten.len();

		self.tcp.checksum = self.tcp.calc_checksum_ipv4(&self.ip, &buf[tcp_header_ends_at..payload_ends_at])
			.expect("failed to compute checksum");

		let mut tcp_header_buf = &mut buf[ip_header_ends_at..tcp_header_ends_at];
		self.tcp.write(&mut tcp_header_buf);

		let mut next_seq = seq.wrapping_add(payload_bytes as u32);
		if self.tcp.syn {
			next_seq = next_seq.wrapping_add(1);
			self.tcp.syn = false;
		}
		if self.tcp.fin {
			next_seq = next_seq.wrapping_add(1);
			self.tcp.fin = false;
		}
		if wrapping_lt(self.send.nxt, next_seq) {
			self.send.nxt = next_seq;
		}
		self.timers.send_times.insert(seq, time::Instant::now());

		nic.send(&buf[..payload_ends_at])?;
		Ok(payload_bytes)
	}

	fn send_rst(&mut self, nic: &mut Iface) -> io::Result<()> {
		self.tcp.rst = true;

		self.tcp.sequence_number = 0;
		self.tcp.acknowledgment_number = 0;
		self.write(nic, self.send.nxt, 0)?;
		Ok(())
	}

	pub(crate) fn on_tick(&mut self, nic: &mut Iface) -> io::Result<()> {
		if let State:: FinWait2 | State::TimeWait = self.state {
			return Ok(());
		}

		let nunacked_data = self.closed_at.unwrap_or(self.send.nxt).wrapping_sub(self.send.una);
		let nunsent_data = self.unacked.len() as u32 - nunacked_data;

		let waited_for = self.timers.send_times.range(self.send.una..).next().map(|t| t.1.elapsed
		());

		let should_retransmit = if let Some(waited_for) = waited_for {
			waited_for > time::Duration::from_secs(1)
			&& waited_for.as_secs_f64() > 1.5 * self.timers.srtt
		} else {
			false
		};

		if should_retransmit {
			let resend = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);
			if resend < self.send.wnd as u32 && self.closed {
				self.tcp.fin = true;
				self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
			}

			self.write(nic, self.send.una, resend as usize)?;
		} else {
			if nunsent_data == 0 && self.closed_at.is_some() {
				return Ok(());
			}

			let allowed = self.send.wnd as u32 - nunacked_data;
			if allowed == 0 {
				return Ok(());
			}

			let send = std::cmp::min(nunsent_data, allowed);
			if send < allowed && self.closed && self.closed_at.is_none() {
				self.tcp.fin = true;
				self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
			}

			self.write(nic, self.send.nxt, send as usize)?;
		}

		Ok(())
	}

	pub(crate) fn on_packet<'a>(
		&mut self,
		nic: &mut Iface,
		iph: Ipv4HeaderSlice<'a>,
		tcph: TcpHeaderSlice<'a>,
		data: &'a [u8],
	) -> io::Result<Available> {
		let seqn = tcph.sequence_number();
		let mut slen = data.len() as u32;
		if tcph.fin() {
			slen += 1;
		};
		if tcph.syn() {
			slen += 1;
		};
		let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
		let okay = if slen == 0 {
			if self.recv.wnd == 0 {
				if seqn != self.recv.nxt {
					false
				} else {
					true
				}
			} else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
				false
			} else {
				true
			}
		} else {
			if self.recv.wnd == 0 {
				false
			} else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
				&& !is_between_wrapped(
				self.recv.nxt.wrapping_sub(1),
				seqn.wrapping_add(slen - 1),
				wend,
			) {
				false
			} else {
				true
			}
		};

		if !okay {
			eprintln!("Not Okay");
			self.write(nic, self.send.nxt, 0)?;
			return Ok(self.availability());
		}

		if !tcph.ack() {
			if tcph.syn() {
				assert!(data.is_empty());
				self.recv.nxt = seqn.wrapping_add(1);
			}
			return Ok(self.availability());
		}

		let ackn = tcph.acknowledgment_number();
		if let State::SynRecvd = self.state {
			if is_between_wrapped(
				self.send.una.wrapping_sub(1),
				ackn,
				self.send.nxt.wrapping_add(1),
			) {
				self.state = State::Estab;
			}
		}

		if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
			if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
				println!("ack for {} (last: {}); prune in {:?}", ackn, self.send.una, self.unacked);
				if !self.unacked.is_empty() {
					let data_start = if self.send.una == self.send.iss {
						self.send.una.wrapping_add(1)
					} else {
						self.send.una
					};
					let acked_data_end = std::cmp::min(ackn.wrapping_sub(data_start) as usize,
													   self.unacked.len());
					self.unacked.drain(..acked_data_end);

					let old = std::mem::replace(&mut self.timers.send_times, BTreeMap::new());

					let una = self.send.una;
					let mut srtt = &mut self.timers.srtt;
					self.timers.send_times.extend(old.into_iter().filter_map(|(seq, sent)| {
						if is_between_wrapped(una, seq, ackn) {
							*srtt = 0.8 * *srtt + (1.0 - 0.8) * sent.elapsed().as_secs_f64();
							None
						} else {
							Some((seq, sent))
						}
					}));
				}
				self.send.una = ackn;
			}
		}

		if let State::FinWait1 = self.state {
			if let Some(closed_at) = self.closed_at {
				if self.send.una == closed_at.wrapping_add(1) {
					self.state = State::FinWait2;
				}
			}
		}

		if !data.is_empty() {
			if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
				let mut unread_data_at = self.recv.nxt.wrapping_sub(seqn) as usize;
				if unread_data_at > data.len() {
					assert_eq!(unread_data_at, data.len() + 1);
					unread_data_at = 0;
				}
				self.incoming.extend(&data[unread_data_at..]);

				self.recv.nxt = seqn.wrapping_add(data.len() as u32);
				self.write(nic, self.send.nxt, 0)?;
			}
		}

		if tcph.fin() {
			match self.state {
				State::FinWait2 => {
					self.recv.nxt = self.recv.nxt.wrapping_add(1);
					self.write(nic, self.send.nxt, 0)?;
					self.state = State::TimeWait;
				},
				_ => unimplemented!(),
			}
		}

		Ok(self.availability())
	}

	pub(crate) fn close(&mut self) -> io::Result<()> {
		self.closed = true;
		match self.state {
			State::SynRecvd | State::Estab => {
				self.state = State::FinWait1;
			},
			State::FinWait1 | State::FinWait2 => {},
			_ => {
				return Err(io::Error::new(
					io::ErrorKind::NotConnected,
					"already closing"
				))
			}
		};
		Ok(())
	}
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
	lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
	wrapping_lt(start, x) && wrapping_lt(x, end)
}