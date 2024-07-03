//! This module holds all the abci event attributes for IBC events emitted
//! during packet-related datagrams.
//!
use core::str;
use core::str::FromStr;

use derive_more::From;
use ibc_core_client_types::Height;
use ibc_core_host_types::identifiers::{ChannelId, ConnectionId, PortId, Sequence};
use ibc_primitives::prelude::*;
use ibc_primitives::Timestamp;
use subtle_encoding::hex;
use tendermint::abci;

use crate::acknowledgement::Acknowledgement;
use crate::channel::Order;
use crate::error::ChannelError;
use crate::timeout::TimeoutHeight;

const PKT_SEQ_ATTRIBUTE_KEY: &str = "packet_sequence";
const PKT_DATA_ATTRIBUTE_KEY: &str = "packet_data";
const PKT_DATA_HEX_ATTRIBUTE_KEY: &str = "packet_data_hex";
const PKT_SRC_PORT_ATTRIBUTE_KEY: &str = "packet_src_port";
const PKT_SRC_CHANNEL_ATTRIBUTE_KEY: &str = "packet_src_channel";
const PKT_DST_PORT_ATTRIBUTE_KEY: &str = "packet_dst_port";
const PKT_DST_CHANNEL_ATTRIBUTE_KEY: &str = "packet_dst_channel";
const PKT_CHANNEL_ORDERING_ATTRIBUTE_KEY: &str = "packet_channel_ordering";
const PKT_TIMEOUT_HEIGHT_ATTRIBUTE_KEY: &str = "packet_timeout_height";
const PKT_TIMEOUT_TIMESTAMP_ATTRIBUTE_KEY: &str = "packet_timeout_timestamp";
const PKT_ACK_ATTRIBUTE_KEY: &str = "packet_ack";
const PKT_ACK_HEX_ATTRIBUTE_KEY: &str = "packet_ack_hex";
const PKT_CONNECTION_ID_ATTRIBUTE_KEY: &str = "packet_connection";

#[cfg_attr(
    feature = "parity-scale-codec",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        scale_info::TypeInfo
    )
)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, From, PartialEq, Eq)]
pub struct PacketDataAttribute {
    pub packet_data: Vec<u8>,
}

impl TryFrom<PacketDataAttribute> for Vec<abci::EventAttribute> {
    type Error = ChannelError;

    fn try_from(attr: PacketDataAttribute) -> Result<Self, Self::Error> {
        let tags = vec![
            (
                PKT_DATA_ATTRIBUTE_KEY,
                str::from_utf8(&attr.packet_data).map_err(|_| ChannelError::NonUtf8PacketData)?,
            )
                .into(),
            (
                PKT_DATA_HEX_ATTRIBUTE_KEY,
                str::from_utf8(&hex::encode(attr.packet_data))
                    .expect("Never fails because hexadecimal is valid UTF8"),
            )
                .into(),
        ];

        Ok(tags)
    }
}

impl TryFrom<Vec<abci::EventAttribute>> for PacketDataAttribute {
    type Error = ChannelError;

    fn try_from(attrs: Vec<abci::EventAttribute>) -> Result<Self, Self::Error> {
        if attrs.len() != 2 {
            return Err(ChannelError::InvalidAttributeCount {
                expected: 2,
                actual: attrs.len(),
            });
        }

        let packet_data = attrs
            .iter()
            .find(|attr| attr.key_bytes() == PKT_DATA_ATTRIBUTE_KEY.as_bytes())
            .map(|attr| attr.value_bytes().to_vec());

        let packet_data_hex = attrs
            .iter()
            .find(|attr| attr.key_bytes() == PKT_DATA_HEX_ATTRIBUTE_KEY.as_bytes())
            .and_then(|attr| attr.value_str().ok());

        match (packet_data, packet_data_hex) {
            (Some(data), Some(hex)) => hex::decode(hex)
                .map_err(|_| ChannelError::InvalidAttributeValue {
                    attribute_value: String::new(),
                })
                .and_then(|decoded_hex| {
                    if data == decoded_hex {
                        Ok(PacketDataAttribute { packet_data: data })
                    } else {
                        // The data and hex attributes do not match
                        Err(ChannelError::MismatchedPacketData)
                    }
                }),
            (Some(data), None) => Ok(PacketDataAttribute { packet_data: data }),
            (None, Some(hex)) => hex::decode(hex)
                .map_err(|_| ChannelError::InvalidAttributeValue {
                    attribute_value: String::new(),
                })
                .map(|decoded| PacketDataAttribute {
                    packet_data: decoded,
                }),
            (None, None) => Err(ChannelError::InvalidAttributeValue {
                attribute_value: String::new(),
            }),
        }
    }
}

#[cfg_attr(
    feature = "parity-scale-codec",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        scale_info::TypeInfo
    )
)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, From, PartialEq, Eq)]
pub struct TimeoutHeightAttribute {
    pub timeout_height: TimeoutHeight,
}

impl From<TimeoutHeightAttribute> for abci::EventAttribute {
    fn from(attr: TimeoutHeightAttribute) -> Self {
        match attr.timeout_height {
            TimeoutHeight::Never => (PKT_TIMEOUT_HEIGHT_ATTRIBUTE_KEY, "0-0").into(),
            TimeoutHeight::At(height) => {
                (PKT_TIMEOUT_HEIGHT_ATTRIBUTE_KEY, height.to_string()).into()
            }
        }
    }
}

impl TryFrom<abci::EventAttribute> for TimeoutHeightAttribute {
    type Error = ChannelError;

    fn try_from(value: abci::EventAttribute) -> Result<Self, Self::Error> {
        if let Ok(key_str) = value.key_str() {
            if key_str != PKT_TIMEOUT_HEIGHT_ATTRIBUTE_KEY {
                return Err(ChannelError::InvalidAttributeKey {
                    attribute_key: key_str.to_string(),
                });
            }
        } else {
            return Err(ChannelError::InvalidAttributeKey {
                attribute_key: String::new(),
            });
        }

        value
            .value_str()
            .map(|value| {
                let height =
                    Height::from_str(value).map_err(|_| ChannelError::InvalidAttributeValue {
                        attribute_value: value.to_string(),
                    })?;
                let timeout_height = TimeoutHeight::from(height);

                Ok(TimeoutHeightAttribute { timeout_height })
            })
            .map_err(|_| ChannelError::InvalidAttributeValue {
                attribute_value: String::new(),
            })?
    }
}

#[cfg_attr(
    feature = "parity-scale-codec",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        scale_info::TypeInfo
    )
)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, From, PartialEq, Eq)]
pub struct TimeoutTimestampAttribute {
    pub timeout_timestamp: Timestamp,
}

impl From<TimeoutTimestampAttribute> for abci::EventAttribute {
    fn from(attr: TimeoutTimestampAttribute) -> Self {
        (
            PKT_TIMEOUT_TIMESTAMP_ATTRIBUTE_KEY,
            attr.timeout_timestamp.nanoseconds().to_string(),
        )
            .into()
    }
}

impl TryFrom<abci::EventAttribute> for TimeoutTimestampAttribute {
    type Error = ChannelError;

    fn try_from(value: abci::EventAttribute) -> Result<Self, Self::Error> {
        if let Ok(key_str) = value.key_str() {
            if key_str != PKT_TIMEOUT_TIMESTAMP_ATTRIBUTE_KEY {
                return Err(ChannelError::InvalidAttributeKey {
                    attribute_key: key_str.to_string(),
                });
            }
        } else {
            return Err(ChannelError::InvalidAttributeKey {
                attribute_key: String::new(),
            });
        }

        value
            .value_str()
            .map(|value| {
                let nanos = value
                    .parse()
                    .map_err(|_| ChannelError::InvalidAttributeValue {
                        attribute_value: value.to_string(),
                    })?;
                let timeout_timestamp = Timestamp::from_nanoseconds(nanos).map_err(|_| {
                    ChannelError::InvalidAttributeValue {
                        attribute_value: value.to_string(),
                    }
                })?;

                Ok(TimeoutTimestampAttribute { timeout_timestamp })
            })
            .map_err(|_| ChannelError::InvalidAttributeValue {
                attribute_value: String::new(),
            })?
    }
}

#[cfg_attr(
    feature = "parity-scale-codec",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        scale_info::TypeInfo
    )
)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, From, PartialEq, Eq)]
pub struct SequenceAttribute {
    pub sequence: Sequence,
}

impl From<SequenceAttribute> for abci::EventAttribute {
    fn from(attr: SequenceAttribute) -> Self {
        (PKT_SEQ_ATTRIBUTE_KEY, attr.sequence.to_string()).into()
    }
}

impl TryFrom<abci::EventAttribute> for SequenceAttribute {
    type Error = ChannelError;

    fn try_from(value: abci::EventAttribute) -> Result<Self, Self::Error> {
        if let Ok(key_str) = value.key_str() {
            if key_str != PKT_SEQ_ATTRIBUTE_KEY {
                return Err(ChannelError::InvalidAttributeKey {
                    attribute_key: key_str.to_string(),
                });
            }
        } else {
            return Err(ChannelError::InvalidAttributeKey {
                attribute_key: String::new(),
            });
        }

        value
            .value_str()
            .map(|value| {
                let sequence =
                    Sequence::from_str(value).map_err(|_| ChannelError::InvalidAttributeValue {
                        attribute_value: value.to_string(),
                    })?;

                Ok(SequenceAttribute { sequence })
            })
            .map_err(|_| ChannelError::InvalidAttributeValue {
                attribute_value: String::new(),
            })?
    }
}

#[cfg_attr(
    feature = "parity-scale-codec",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        scale_info::TypeInfo
    )
)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, From, PartialEq, Eq)]
pub struct SrcPortIdAttribute {
    pub src_port_id: PortId,
}

impl From<SrcPortIdAttribute> for abci::EventAttribute {
    fn from(attr: SrcPortIdAttribute) -> Self {
        (PKT_SRC_PORT_ATTRIBUTE_KEY, attr.src_port_id.as_str()).into()
    }
}

impl TryFrom<abci::EventAttribute> for SrcPortIdAttribute {
    type Error = ChannelError;

    fn try_from(value: abci::EventAttribute) -> Result<Self, Self::Error> {
        if let Ok(key_str) = value.key_str() {
            if key_str != PKT_SRC_PORT_ATTRIBUTE_KEY {
                return Err(ChannelError::InvalidAttributeKey {
                    attribute_key: key_str.to_string(),
                });
            }
        } else {
            return Err(ChannelError::InvalidAttributeKey {
                attribute_key: String::new(),
            });
        }

        value
            .value_str()
            .map(|value| {
                let port_id =
                    PortId::from_str(value).map_err(|_| ChannelError::InvalidAttributeValue {
                        attribute_value: value.to_string(),
                    })?;

                Ok(SrcPortIdAttribute {
                    src_port_id: port_id,
                })
            })
            .map_err(|_| ChannelError::InvalidAttributeValue {
                attribute_value: String::new(),
            })?
    }
}

#[cfg_attr(
    feature = "parity-scale-codec",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        scale_info::TypeInfo
    )
)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, From, PartialEq, Eq)]
pub struct SrcChannelIdAttribute {
    pub src_channel_id: ChannelId,
}

impl From<SrcChannelIdAttribute> for abci::EventAttribute {
    fn from(attr: SrcChannelIdAttribute) -> Self {
        (PKT_SRC_CHANNEL_ATTRIBUTE_KEY, attr.src_channel_id.as_str()).into()
    }
}

impl TryFrom<abci::EventAttribute> for SrcChannelIdAttribute {
    type Error = ChannelError;

    fn try_from(value: abci::EventAttribute) -> Result<Self, Self::Error> {
        if let Ok(key_str) = value.key_str() {
            if key_str != PKT_SRC_CHANNEL_ATTRIBUTE_KEY {
                return Err(ChannelError::InvalidAttributeKey {
                    attribute_key: key_str.to_string(),
                });
            }
        } else {
            return Err(ChannelError::InvalidAttributeKey {
                attribute_key: String::new(),
            });
        }

        value
            .value_str()
            .map(|value| {
                let src_channel_id = ChannelId::from_str(value).map_err(|_| {
                    ChannelError::InvalidAttributeValue {
                        attribute_value: value.to_string(),
                    }
                })?;

                Ok(SrcChannelIdAttribute { src_channel_id })
            })
            .map_err(|_| ChannelError::InvalidAttributeValue {
                attribute_value: String::new(),
            })?
    }
}

#[cfg_attr(
    feature = "parity-scale-codec",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        scale_info::TypeInfo
    )
)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, From, PartialEq, Eq)]
pub struct DstPortIdAttribute {
    pub dst_port_id: PortId,
}

impl From<DstPortIdAttribute> for abci::EventAttribute {
    fn from(attr: DstPortIdAttribute) -> Self {
        (PKT_DST_PORT_ATTRIBUTE_KEY, attr.dst_port_id.as_str()).into()
    }
}

impl TryFrom<abci::EventAttribute> for DstPortIdAttribute {
    type Error = ChannelError;

    fn try_from(value: abci::EventAttribute) -> Result<Self, Self::Error> {
        if let Ok(key_str) = value.key_str() {
            if key_str != PKT_DST_PORT_ATTRIBUTE_KEY {
                return Err(ChannelError::InvalidAttributeKey {
                    attribute_key: key_str.to_string(),
                });
            }
        } else {
            return Err(ChannelError::InvalidAttributeKey {
                attribute_key: String::new(),
            });
        }

        value
            .value_str()
            .map(|value| {
                let port_id =
                    PortId::from_str(value).map_err(|_| ChannelError::InvalidAttributeValue {
                        attribute_value: value.to_string(),
                    })?;

                Ok(DstPortIdAttribute {
                    dst_port_id: port_id,
                })
            })
            .map_err(|_| ChannelError::InvalidAttributeValue {
                attribute_value: String::new(),
            })?
    }
}

#[cfg_attr(
    feature = "parity-scale-codec",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        scale_info::TypeInfo
    )
)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, From, PartialEq, Eq)]
pub struct DstChannelIdAttribute {
    pub dst_channel_id: ChannelId,
}

impl From<DstChannelIdAttribute> for abci::EventAttribute {
    fn from(attr: DstChannelIdAttribute) -> Self {
        (PKT_DST_CHANNEL_ATTRIBUTE_KEY, attr.dst_channel_id.as_str()).into()
    }
}

impl TryFrom<abci::EventAttribute> for DstChannelIdAttribute {
    type Error = ChannelError;

    fn try_from(value: abci::EventAttribute) -> Result<Self, Self::Error> {
        if let Ok(key_str) = value.key_str() {
            if key_str != PKT_DST_CHANNEL_ATTRIBUTE_KEY {
                return Err(ChannelError::InvalidAttributeKey {
                    attribute_key: key_str.to_string(),
                });
            }
        } else {
            return Err(ChannelError::InvalidAttributeKey {
                attribute_key: String::new(),
            });
        }

        value
            .value_str()
            .map(|value| {
                let dst_channel_id = ChannelId::from_str(value).map_err(|_| {
                    ChannelError::InvalidAttributeValue {
                        attribute_value: value.to_string(),
                    }
                })?;

                Ok(DstChannelIdAttribute { dst_channel_id })
            })
            .map_err(|_| ChannelError::InvalidAttributeValue {
                attribute_value: String::new(),
            })?
    }
}

#[cfg_attr(
    feature = "parity-scale-codec",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        scale_info::TypeInfo
    )
)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, From, PartialEq, Eq)]
pub struct ChannelOrderingAttribute {
    pub order: Order,
}

impl From<ChannelOrderingAttribute> for abci::EventAttribute {
    fn from(attr: ChannelOrderingAttribute) -> Self {
        (PKT_CHANNEL_ORDERING_ATTRIBUTE_KEY, attr.order.as_str()).into()
    }
}

impl TryFrom<abci::EventAttribute> for ChannelOrderingAttribute {
    type Error = ChannelError;

    fn try_from(value: abci::EventAttribute) -> Result<Self, Self::Error> {
        if let Ok(key_str) = value.key_str() {
            if key_str != PKT_CHANNEL_ORDERING_ATTRIBUTE_KEY {
                return Err(ChannelError::InvalidAttributeKey {
                    attribute_key: key_str.to_string(),
                });
            }
        } else {
            return Err(ChannelError::InvalidAttributeKey {
                attribute_key: String::new(),
            });
        }

        value
            .value_str()
            .map(|value| {
                let order =
                    Order::from_str(value).map_err(|_| ChannelError::InvalidAttributeValue {
                        attribute_value: value.to_string(),
                    })?;

                Ok(ChannelOrderingAttribute { order })
            })
            .map_err(|_| ChannelError::InvalidAttributeValue {
                attribute_value: String::new(),
            })?
    }
}

#[cfg_attr(
    feature = "parity-scale-codec",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        scale_info::TypeInfo
    )
)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, From, PartialEq, Eq)]
pub struct PacketConnectionIdAttribute {
    pub connection_id: ConnectionId,
}

impl From<PacketConnectionIdAttribute> for abci::EventAttribute {
    fn from(attr: PacketConnectionIdAttribute) -> Self {
        (PKT_CONNECTION_ID_ATTRIBUTE_KEY, attr.connection_id.as_str()).into()
    }
}

#[cfg_attr(
    feature = "parity-scale-codec",
    derive(
        parity_scale_codec::Encode,
        parity_scale_codec::Decode,
        scale_info::TypeInfo
    )
)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, From, PartialEq, Eq)]
pub struct AcknowledgementAttribute {
    pub acknowledgement: Acknowledgement,
}

impl TryFrom<AcknowledgementAttribute> for Vec<abci::EventAttribute> {
    type Error = ChannelError;

    fn try_from(attr: AcknowledgementAttribute) -> Result<Self, Self::Error> {
        let tags = vec![
            (
                PKT_ACK_ATTRIBUTE_KEY,
                // Note: this attribute forces us to assume that Packet data
                // is valid UTF-8, even though the standard doesn't require
                // it. It has been deprecated in ibc-go. It will be removed
                // in the future.
                str::from_utf8(attr.acknowledgement.as_bytes())
                    .map_err(|_| ChannelError::NonUtf8PacketData)?,
            )
                .into(),
            (
                PKT_ACK_HEX_ATTRIBUTE_KEY,
                str::from_utf8(&hex::encode(attr.acknowledgement))
                    .expect("Never fails because hexadecimal is always valid UTF-8"),
            )
                .into(),
        ];

        Ok(tags)
    }
}
