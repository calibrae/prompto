//! Wake-on-LAN — UDP magic packet, no crate.
//!
//! Packet layout: 6 × 0xFF followed by 16 × the target MAC. 102 bytes total.
//! Sent to UDP broadcast 255.255.255.255:9 from a SO_BROADCAST socket.

use anyhow::{Context, Result, anyhow};
use tokio::net::UdpSocket;

pub const WOL_PORT: u16 = 9;
pub const PACKET_LEN: usize = 6 + 16 * 6;

/// Build the 102-byte magic packet for the given MAC.
pub fn magic_packet(mac: [u8; 6]) -> [u8; PACKET_LEN] {
    let mut packet = [0u8; PACKET_LEN];
    for b in packet.iter_mut().take(6) {
        *b = 0xff;
    }
    for i in 0..16 {
        let start = 6 + i * 6;
        packet[start..start + 6].copy_from_slice(&mac);
    }
    packet
}

/// Parse a MAC string. Accepts `aa:bb:cc:dd:ee:ff`, `aa-bb-...`, or bare
/// `aabbccddeeff`. Case-insensitive.
pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let cleaned: String = s
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.'))
        .collect();
    if cleaned.len() != 12 {
        return Err(anyhow!(
            "MAC must be 12 hex chars (got {} after stripping separators): {s:?}",
            cleaned.len()
        ));
    }
    let mut out = [0u8; 6];
    for (i, byte) in out.iter_mut().enumerate() {
        let pair = &cleaned[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(pair, 16)
            .with_context(|| format!("MAC byte {i} (\"{pair}\") is not hex"))?;
    }
    Ok(out)
}

/// Send a WOL magic packet to the broadcast address. Bound to 0.0.0.0:0 with
/// SO_BROADCAST. The OS picks the outbound interface based on the routing
/// table; on hosts with multiple subnets, broadcast goes out the default route.
pub async fn send(mac: [u8; 6]) -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .context("bind UDP socket for WOL")?;
    socket.set_broadcast(true).context("SO_BROADCAST")?;
    let packet = magic_packet(mac);
    socket
        .send_to(&packet, ("255.255.255.255", WOL_PORT))
        .await
        .context("send WOL packet")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_length_is_102() {
        let p = magic_packet([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(p.len(), 102);
    }

    #[test]
    fn packet_starts_with_six_ff() {
        let p = magic_packet([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(&p[..6], &[0xff; 6]);
    }

    #[test]
    fn packet_contains_sixteen_mac_repetitions() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let p = magic_packet(mac);
        for i in 0..16 {
            let start = 6 + i * 6;
            assert_eq!(&p[start..start + 6], &mac, "rep {i}");
        }
    }

    #[test]
    fn parse_mac_colons() {
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn parse_mac_dashes() {
        assert_eq!(
            parse_mac("AA-BB-CC-DD-EE-FF").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn parse_mac_bare() {
        assert_eq!(
            parse_mac("aabbccddeeff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn parse_mac_mixed_separators() {
        assert_eq!(
            parse_mac("aa.bb.cc-dd:ee:ff").unwrap(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    fn parse_mac_rejects_wrong_length() {
        assert!(parse_mac("aa:bb:cc:dd:ee").is_err());
        assert!(parse_mac("").is_err());
        assert!(parse_mac("aa:bb:cc:dd:ee:ff:00").is_err());
    }

    #[test]
    fn parse_mac_rejects_non_hex() {
        assert!(parse_mac("aa:bb:cc:dd:ee:zz").is_err());
    }
}
