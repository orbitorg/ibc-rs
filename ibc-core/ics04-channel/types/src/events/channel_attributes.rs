//! This module holds all the abci event attributes for IBC events emitted
//! during the channel handshake.
use alloc::string::ToString;
use core::str::FromStr;
use std::string::String;

use derive_more::From;
use ibc_core_host_types::identifiers::{ChannelId, ConnectionId, PortId};
use tendermint::abci;

use crate::error::ChannelError;
use crate::Version;
const CONNECTION_ID_ATTRIBUTE_KEY: &str = "connection_id";
const CHANNEL_ID_ATTRIBUTE_KEY: &str = "channel_id";
const PORT_ID_ATTRIBUTE_KEY: &str = "port_id";
/// This attribute key is public so that OpenInit can use it to convert itself
/// to an `AbciEvent`
pub(super) const COUNTERPARTY_CHANNEL_ID_ATTRIBUTE_KEY: &str = "counterparty_channel_id";
const COUNTERPARTY_PORT_ID_ATTRIBUTE_KEY: &str = "counterparty_port_id";
const VERSION_ATTRIBUTE_KEY: &str = "version";

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
pub struct PortIdAttribute {
    pub port_id: PortId,
}

impl From<PortIdAttribute> for abci::EventAttribute {
    fn from(attr: PortIdAttribute) -> Self {
        (PORT_ID_ATTRIBUTE_KEY, attr.port_id.as_str()).into()
    }
}

impl TryFrom<abci::EventAttribute> for PortIdAttribute {
    type Error = ChannelError;
    fn try_from(value: abci::EventAttribute) -> Result<Self, Self::Error> {
        if let Ok(key_str) = value.key_str() {
            if key_str != PORT_ID_ATTRIBUTE_KEY {
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
                let port_id = PortId::from_str(value)?;

                Ok(PortIdAttribute { port_id })
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
pub struct ChannelIdAttribute {
    pub channel_id: ChannelId,
}

impl From<ChannelIdAttribute> for abci::EventAttribute {
    fn from(attr: ChannelIdAttribute) -> Self {
        (CHANNEL_ID_ATTRIBUTE_KEY, attr.channel_id.as_str()).into()
    }
}

impl TryFrom<abci::EventAttribute> for ChannelIdAttribute {
    type Error = ChannelError;
    fn try_from(value: abci::EventAttribute) -> Result<Self, Self::Error> {
        if let Ok(key_str) = value.key_str() {
            if key_str != CHANNEL_ID_ATTRIBUTE_KEY {
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
                let channel_id = ChannelId::from_str(value).map_err(|_| {
                    ChannelError::InvalidAttributeValue {
                        attribute_value: value.to_string(),
                    }
                })?;

                Ok(ChannelIdAttribute { channel_id })
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
pub struct CounterpartyPortIdAttribute {
    pub counterparty_port_id: PortId,
}

impl From<CounterpartyPortIdAttribute> for abci::EventAttribute {
    fn from(attr: CounterpartyPortIdAttribute) -> Self {
        (
            COUNTERPARTY_PORT_ID_ATTRIBUTE_KEY,
            attr.counterparty_port_id.as_str(),
        )
            .into()
    }
}

impl TryFrom<abci::EventAttribute> for CounterpartyPortIdAttribute {
    type Error = ChannelError;

    fn try_from(value: abci::EventAttribute) -> Result<Self, Self::Error> {
        if let Ok(key_str) = value.key_str() {
            if key_str != COUNTERPARTY_PORT_ID_ATTRIBUTE_KEY {
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
                let counterparty_port_id =
                    PortId::from_str(value).map_err(|_| ChannelError::InvalidAttributeValue {
                        attribute_value: value.to_string(),
                    })?;

                Ok(CounterpartyPortIdAttribute {
                    counterparty_port_id,
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
pub struct CounterpartyChannelIdAttribute {
    pub counterparty_channel_id: ChannelId,
}

impl From<CounterpartyChannelIdAttribute> for abci::EventAttribute {
    fn from(attr: CounterpartyChannelIdAttribute) -> Self {
        (
            COUNTERPARTY_CHANNEL_ID_ATTRIBUTE_KEY,
            attr.counterparty_channel_id.as_str(),
        )
            .into()
    }
}

impl TryFrom<abci::EventAttribute> for CounterpartyChannelIdAttribute {
    type Error = ChannelError;

    fn try_from(value: abci::EventAttribute) -> Result<Self, Self::Error> {
        if let Ok(key_str) = value.key_str() {
            if key_str != COUNTERPARTY_CHANNEL_ID_ATTRIBUTE_KEY {
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
                let counterparty_channel_id = ChannelId::from_str(value).map_err(|_| {
                    ChannelError::InvalidAttributeValue {
                        attribute_value: value.to_string(),
                    }
                })?;

                Ok(CounterpartyChannelIdAttribute {
                    counterparty_channel_id,
                })
            })
            .map_err(|_| ChannelError::InvalidAttributeValue {
                attribute_value: String::new(),
            })?
    }
}

impl AsRef<ChannelId> for CounterpartyChannelIdAttribute {
    fn as_ref(&self) -> &ChannelId {
        &self.counterparty_channel_id
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
pub struct ConnectionIdAttribute {
    pub connection_id: ConnectionId,
}

impl From<ConnectionIdAttribute> for abci::EventAttribute {
    fn from(attr: ConnectionIdAttribute) -> Self {
        (CONNECTION_ID_ATTRIBUTE_KEY, attr.connection_id.as_str()).into()
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
pub struct VersionAttribute {
    pub version: Version,
}

impl From<VersionAttribute> for abci::EventAttribute {
    fn from(attr: VersionAttribute) -> Self {
        (VERSION_ATTRIBUTE_KEY, attr.version.as_str()).into()
    }
}

impl TryFrom<abci::EventAttribute> for VersionAttribute {
    type Error = ChannelError;

    fn try_from(value: abci::EventAttribute) -> Result<Self, Self::Error> {
        if let Ok(key_str) = value.key_str() {
            if key_str != VERSION_ATTRIBUTE_KEY {
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
                let version =
                    Version::from_str(value).map_err(|_| ChannelError::InvalidAttributeValue {
                        attribute_value: value.to_string(),
                    })?;

                Ok(VersionAttribute { version })
            })
            .map_err(|_| ChannelError::InvalidAttributeValue {
                attribute_value: String::new(),
            })?
    }
}
