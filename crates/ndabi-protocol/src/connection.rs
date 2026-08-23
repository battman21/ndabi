//! Enforce the NDABI v0.2 connection and request state machines.
//!
//! The frame codec proves bytes. This module proves direction, negotiation, correlation, sequence, budgets, and terminal receipt.

use std::collections::BTreeMap;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::{
    authenticate_request, decode_transport, encode_transport, transport_frame_bytes, Authority,
    ProtocolError, TransportDirection, TransportFields, TransportFrame, TransportKind,
    TRANSPORT_MIN_FRAME_BYTES,
};

pub const FEATURE_STREAMING: u32 = 0x0000_0001;
pub const FEATURE_CANCELLATION: u32 = 0x0000_0002;
pub const KNOWN_TRANSPORT_FEATURES: u32 = FEATURE_STREAMING | FEATURE_CANCELLATION;

const VERSION_MAJOR: u16 = 2;
const VERSION_MINOR: u16 = 0;
const NEGOTIATION_PAYLOAD_BYTES: usize = 8;
const TRANSPORT_RECEIPT_DOMAIN: &[u8] = b"ndabi/wire/v2/execution-receipt";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportRole {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportPhase {
    Provisioned,
    HelloSent,
    HelloReceived,
    Ready,
    Refused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportConfig {
    pub features: u32,
    pub maximum_frame_bytes: u32,
    pub maximum_chunk_bytes: u32,
    pub maximum_in_flight: u32,
}

impl TransportConfig {
    pub fn new(
        features: u32,
        maximum_frame_bytes: u32,
        maximum_chunk_bytes: u32,
        maximum_in_flight: u32,
    ) -> Result<Self, ProtocolError> {
        let minimum_negotiation_frame =
            (TRANSPORT_MIN_FRAME_BYTES + NEGOTIATION_PAYLOAD_BYTES) as u32;
        if features & !KNOWN_TRANSPORT_FEATURES != 0
            || maximum_frame_bytes < minimum_negotiation_frame
            || maximum_chunk_bytes == 0
            || maximum_chunk_bytes
                > maximum_frame_bytes.saturating_sub(TRANSPORT_MIN_FRAME_BYTES as u32)
            || maximum_in_flight == 0
        {
            return Err(ProtocolError::TransportConfiguration);
        }
        Ok(Self {
            features,
            maximum_frame_bytes,
            maximum_chunk_bytes,
            maximum_in_flight,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NegotiatedTransport {
    pub features: u32,
    pub maximum_frame_bytes: u32,
    pub maximum_chunk_bytes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredRequest {
    pub nonce: u64,
    pub result_shape: u32,
    pub result_budget: u32,
    pub row_budget: u32,
}

#[derive(Clone, Copy)]
struct Offer {
    minimum_major: u16,
    maximum_major: u16,
    features: u32,
    maximum_frame_bytes: u32,
    maximum_chunk_bytes: u32,
}

struct RequestRecord {
    request_digest: [u8; 32],
    result_shape: u32,
    result_budget: u32,
    row_budget: u32,
    state: RequestState,
}

enum RequestState {
    Pending { cancel_requested: bool },
    Streaming(Box<StreamingState>),
}

struct StreamingState {
    next_sequence: u32,
    received_bytes: u64,
    expected_rows: Option<u32>,
    result_digest: blake3::Hasher,
    cancel_requested: bool,
}

pub struct TransportConnection {
    authority: Authority,
    role: TransportRole,
    config: TransportConfig,
    phase: TransportPhase,
    offer: Option<Offer>,
    negotiated: Option<NegotiatedTransport>,
    requests: BTreeMap<u64, RequestRecord>,
    last_registered_nonce: u64,
}

impl TransportConnection {
    pub fn new(authority: Authority, role: TransportRole, config: TransportConfig) -> Self {
        Self {
            authority,
            role,
            config,
            phase: TransportPhase::Provisioned,
            offer: None,
            negotiated: None,
            requests: BTreeMap::new(),
            last_registered_nonce: 0,
        }
    }

    pub fn phase(&self) -> TransportPhase {
        self.phase
    }

    pub fn negotiated(&self) -> Option<NegotiatedTransport> {
        self.negotiated
    }

    pub fn register_v1_request(
        &mut self,
        request_frame: &[u8],
    ) -> Result<RegisteredRequest, ProtocolError> {
        let request = authenticate_request(&self.authority, request_frame)?;
        if request.deadline_unix_us == 0
            || request.deadline_unix_us > self.authority.expires_unix_us
        {
            return Err(ProtocolError::DeadlineBeyondAuthority);
        }
        if request.result_budget == 0 || request.row_budget == 0 {
            return Err(ProtocolError::ZeroBudget);
        }
        let registered = RegisteredRequest {
            nonce: request.nonce,
            result_shape: request.operation.result_shape,
            result_budget: request.result_budget,
            row_budget: request.row_budget,
        };
        self.register_request(request_frame, registered)?;
        Ok(registered)
    }

    fn register_request(
        &mut self,
        request_frame: &[u8],
        request: RegisteredRequest,
    ) -> Result<(), ProtocolError> {
        if self.phase != TransportPhase::Ready {
            return Err(ProtocolError::ConnectionState);
        }
        if request_frame.is_empty()
            || request.nonce == 0
            || request.nonce <= self.last_registered_nonce
            || request.result_shape == 0
            || request.result_budget == 0
            || request.row_budget == 0
        {
            return Err(ProtocolError::NonCanonicalFrame);
        }
        if self.requests.len() >= self.config.maximum_in_flight as usize {
            return Err(ProtocolError::RequestLimitExceeded);
        }
        self.requests.insert(
            request.nonce,
            RequestRecord {
                request_digest: *blake3::hash(request_frame).as_bytes(),
                result_shape: request.result_shape,
                result_budget: request.result_budget,
                row_budget: request.row_budget,
                state: RequestState::Pending {
                    cancel_requested: false,
                },
            },
        );
        self.last_registered_nonce = request.nonce;
        Ok(())
    }

    pub fn result_receipt(
        &self,
        nonce: u64,
        rows: u32,
        result: &[u8],
    ) -> Result<[u8; 32], ProtocolError> {
        let request = self
            .requests
            .get(&nonce)
            .ok_or(ProtocolError::UnknownCorrelation)?;
        let result_digest = *blake3::hash(result).as_bytes();
        Ok(transport_receipt(
            &self.authority,
            request.request_digest,
            nonce,
            rows,
            result_digest,
        ))
    }

    pub fn stream_receipt(&self, nonce: u64, rows: u32) -> Result<[u8; 32], ProtocolError> {
        let request = self
            .requests
            .get(&nonce)
            .ok_or(ProtocolError::UnknownCorrelation)?;
        let RequestState::Streaming(stream) = &request.state else {
            return Err(ProtocolError::ConnectionState);
        };
        let digest = *stream.result_digest.clone().finalize().as_bytes();
        Ok(transport_receipt(
            &self.authority,
            request.request_digest,
            nonce,
            rows,
            digest,
        ))
    }

    pub fn encode(
        &mut self,
        kind: TransportKind,
        fields: TransportFields,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<(), ProtocolError> {
        let direction = self.outbound_direction();
        encode_transport(&self.authority, direction, kind, fields, payload, output)?;
        if let Err(error) = self.apply(true, kind, fields, payload) {
            output.fill(0);
            return Err(error);
        }
        Ok(())
    }

    pub fn decode<'a>(
        &mut self,
        frame: &'a [u8],
        now_unix_us: u64,
    ) -> Result<TransportFrame<'a>, ProtocolError> {
        let maximum_payload = self
            .config
            .maximum_frame_bytes
            .saturating_sub(TRANSPORT_MIN_FRAME_BYTES as u32);
        let decoded = decode_transport(
            &self.authority,
            self.inbound_direction(),
            frame,
            maximum_payload,
            now_unix_us,
        )?;
        self.apply(false, decoded.kind, decoded.fields, decoded.payload)?;
        Ok(decoded)
    }

    fn apply(
        &mut self,
        outbound: bool,
        kind: TransportKind,
        fields: TransportFields,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        match self.phase {
            TransportPhase::Provisioned => self.apply_provisioned(outbound, kind, fields, payload),
            TransportPhase::HelloSent => {
                self.apply_client_negotiation(outbound, kind, fields, payload)
            }
            TransportPhase::HelloReceived => {
                self.apply_server_negotiation(outbound, kind, fields, payload)
            }
            TransportPhase::Ready => self.apply_ready(outbound, kind, fields, payload),
            TransportPhase::Refused => Err(ProtocolError::ConnectionState),
        }
    }

    fn apply_provisioned(
        &mut self,
        outbound: bool,
        kind: TransportKind,
        fields: TransportFields,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        let correct_direction = match self.role {
            TransportRole::Client => outbound,
            TransportRole::Server => !outbound,
        };
        if !correct_direction || kind != TransportKind::Hello {
            return Err(ProtocolError::ConnectionState);
        }
        let offer = parse_offer(fields, payload)?;
        if offer.minimum_major > VERSION_MAJOR || offer.maximum_major < VERSION_MAJOR {
            return Err(ProtocolError::UnsupportedFrame);
        }
        if self.role == TransportRole::Client
            && (offer.features != self.config.features
                || offer.maximum_frame_bytes != self.config.maximum_frame_bytes
                || offer.maximum_chunk_bytes != self.config.maximum_chunk_bytes)
        {
            return Err(ProtocolError::TransportConfiguration);
        }
        self.offer = Some(offer);
        self.phase = match self.role {
            TransportRole::Client => TransportPhase::HelloSent,
            TransportRole::Server => TransportPhase::HelloReceived,
        };
        Ok(())
    }

    fn apply_client_negotiation(
        &mut self,
        outbound: bool,
        kind: TransportKind,
        fields: TransportFields,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        if self.role != TransportRole::Client || outbound {
            return Err(ProtocolError::ConnectionState);
        }
        if kind == TransportKind::Error && fields.correlation_nonce == 0 {
            self.phase = TransportPhase::Refused;
            return Ok(());
        }
        if kind != TransportKind::Accept {
            return Err(ProtocolError::ConnectionState);
        }
        let negotiated = self.validate_accept(fields, payload)?;
        self.negotiated = Some(negotiated);
        self.phase = TransportPhase::Ready;
        Ok(())
    }

    fn apply_server_negotiation(
        &mut self,
        outbound: bool,
        kind: TransportKind,
        fields: TransportFields,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        if self.role != TransportRole::Server || !outbound {
            return Err(ProtocolError::ConnectionState);
        }
        if kind == TransportKind::Error && fields.correlation_nonce == 0 {
            self.phase = TransportPhase::Refused;
            return Ok(());
        }
        if kind != TransportKind::Accept {
            return Err(ProtocolError::ConnectionState);
        }
        let negotiated = self.validate_accept(fields, payload)?;
        self.negotiated = Some(negotiated);
        self.phase = TransportPhase::Ready;
        Ok(())
    }

    fn validate_accept(
        &self,
        fields: TransportFields,
        payload: &[u8],
    ) -> Result<NegotiatedTransport, ProtocolError> {
        let offer = self.offer.ok_or(ProtocolError::ConnectionState)?;
        let selected_major = get_u16(payload, 0)?;
        let selected_minor = get_u16(payload, 2)?;
        let maximum_chunk_bytes = get_u32(payload, 4)?;
        if selected_major != VERSION_MAJOR
            || selected_minor != VERSION_MINOR
            || fields.features & !offer.features != 0
            || fields.features & !self.config.features != 0
            || fields.maximum_frame_bytes() > offer.maximum_frame_bytes
            || fields.maximum_frame_bytes() > self.config.maximum_frame_bytes
            || maximum_chunk_bytes > offer.maximum_chunk_bytes
            || maximum_chunk_bytes > self.config.maximum_chunk_bytes
            || maximum_chunk_bytes
                > fields
                    .maximum_frame_bytes()
                    .saturating_sub(TRANSPORT_MIN_FRAME_BYTES as u32)
        {
            return Err(ProtocolError::ConnectionState);
        }
        Ok(NegotiatedTransport {
            features: fields.features,
            maximum_frame_bytes: fields.maximum_frame_bytes(),
            maximum_chunk_bytes,
        })
    }

    fn apply_ready(
        &mut self,
        outbound: bool,
        kind: TransportKind,
        fields: TransportFields,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        let negotiated = self.negotiated.ok_or(ProtocolError::ConnectionState)?;
        if transport_frame_bytes(payload.len())? > negotiated.maximum_frame_bytes as usize {
            return Err(ProtocolError::LengthMismatch);
        }
        match (self.role, outbound, kind) {
            (TransportRole::Client, true, TransportKind::Cancel)
            | (TransportRole::Server, false, TransportKind::Cancel) => {
                self.apply_cancel(fields.correlation_nonce)
            }
            (TransportRole::Client, false, TransportKind::Result)
            | (TransportRole::Server, true, TransportKind::Result) => {
                self.apply_result(fields, payload)
            }
            (TransportRole::Client, false, TransportKind::Error)
            | (TransportRole::Server, true, TransportKind::Error) => self.apply_error(fields),
            (TransportRole::Client, false, TransportKind::StreamStart)
            | (TransportRole::Server, true, TransportKind::StreamStart) => {
                self.apply_stream_start(fields)
            }
            (TransportRole::Client, false, TransportKind::StreamChunk)
            | (TransportRole::Server, true, TransportKind::StreamChunk) => {
                self.apply_stream_chunk(fields, payload)
            }
            (TransportRole::Client, false, TransportKind::StreamEnd)
            | (TransportRole::Server, true, TransportKind::StreamEnd) => {
                self.apply_stream_end(fields)
            }
            _ => Err(ProtocolError::ConnectionState),
        }
    }

    fn apply_cancel(&mut self, nonce: u64) -> Result<(), ProtocolError> {
        self.require_feature(FEATURE_CANCELLATION)?;
        let request = self
            .requests
            .get_mut(&nonce)
            .ok_or(ProtocolError::UnknownCorrelation)?;
        let cancel_requested = match &mut request.state {
            RequestState::Pending { cancel_requested } => cancel_requested,
            RequestState::Streaming(stream) => &mut stream.cancel_requested,
        };
        if *cancel_requested {
            return Err(ProtocolError::ConnectionState);
        }
        *cancel_requested = true;
        Ok(())
    }

    fn apply_result(
        &mut self,
        fields: TransportFields,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        let request = self
            .requests
            .get(&fields.correlation_nonce)
            .ok_or(ProtocolError::UnknownCorrelation)?;
        if !matches!(request.state, RequestState::Pending { .. }) {
            return Err(ProtocolError::ConnectionState);
        }
        if fields.result_shape != request.result_shape {
            return Err(ProtocolError::OutputShape);
        }
        if fields.rows > request.row_budget {
            return Err(ProtocolError::RowBudgetExceeded);
        }
        if payload.len() > request.result_budget as usize {
            return Err(ProtocolError::ResultBudgetExceeded);
        }
        let result_digest = *blake3::hash(payload).as_bytes();
        let mut expected = transport_receipt(
            &self.authority,
            request.request_digest,
            fields.correlation_nonce,
            fields.rows,
            result_digest,
        );
        let matches = expected.ct_eq(&fields.execution_receipt).unwrap_u8() == 1;
        expected.zeroize();
        if !matches {
            return Err(ProtocolError::ReceiptMismatch);
        }
        self.requests.remove(&fields.correlation_nonce);
        Ok(())
    }

    fn apply_error(&mut self, fields: TransportFields) -> Result<(), ProtocolError> {
        if fields.correlation_nonce == 0 {
            return Err(ProtocolError::ConnectionState);
        }
        let request = self
            .requests
            .get(&fields.correlation_nonce)
            .ok_or(ProtocolError::UnknownCorrelation)?;
        if fields.error_code == 7 && !request.cancel_requested() {
            return Err(ProtocolError::ConnectionState);
        }
        self.requests.remove(&fields.correlation_nonce);
        Ok(())
    }

    fn apply_stream_start(&mut self, fields: TransportFields) -> Result<(), ProtocolError> {
        self.require_feature(FEATURE_STREAMING)?;
        let request = self
            .requests
            .get_mut(&fields.correlation_nonce)
            .ok_or(ProtocolError::UnknownCorrelation)?;
        let RequestState::Pending { cancel_requested } = request.state else {
            return Err(ProtocolError::ConnectionState);
        };
        if fields.result_shape != request.result_shape {
            return Err(ProtocolError::OutputShape);
        }
        if fields.rows != u32::MAX && fields.rows > request.row_budget {
            return Err(ProtocolError::RowBudgetExceeded);
        }
        request.state = RequestState::Streaming(Box::new(StreamingState {
            next_sequence: 1,
            received_bytes: 0,
            expected_rows: (fields.rows != u32::MAX).then_some(fields.rows),
            result_digest: blake3::Hasher::new(),
            cancel_requested,
        }));
        Ok(())
    }

    fn apply_stream_chunk(
        &mut self,
        fields: TransportFields,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        self.require_feature(FEATURE_STREAMING)?;
        let maximum_chunk_bytes = self
            .negotiated
            .ok_or(ProtocolError::ConnectionState)?
            .maximum_chunk_bytes;
        let request = self
            .requests
            .get_mut(&fields.correlation_nonce)
            .ok_or(ProtocolError::UnknownCorrelation)?;
        let RequestState::Streaming(stream) = &mut request.state else {
            return Err(ProtocolError::ConnectionState);
        };
        if fields.sequence != stream.next_sequence {
            return Err(ProtocolError::SequenceMismatch);
        }
        let next_bytes = stream
            .received_bytes
            .checked_add(payload.len() as u64)
            .ok_or(ProtocolError::ResultBudgetExceeded)?;
        if payload.len() > maximum_chunk_bytes as usize || next_bytes > request.result_budget as u64
        {
            return Err(ProtocolError::ResultBudgetExceeded);
        }
        let following_sequence = stream
            .next_sequence
            .checked_add(1)
            .ok_or(ProtocolError::SequenceMismatch)?;
        stream.result_digest.update(payload);
        stream.received_bytes = next_bytes;
        stream.next_sequence = following_sequence;
        Ok(())
    }

    fn apply_stream_end(&mut self, fields: TransportFields) -> Result<(), ProtocolError> {
        self.require_feature(FEATURE_STREAMING)?;
        let request = self
            .requests
            .get(&fields.correlation_nonce)
            .ok_or(ProtocolError::UnknownCorrelation)?;
        let RequestState::Streaming(stream) = &request.state else {
            return Err(ProtocolError::ConnectionState);
        };
        if fields.sequence != stream.next_sequence {
            return Err(ProtocolError::SequenceMismatch);
        }
        if fields.result_shape != request.result_shape {
            return Err(ProtocolError::OutputShape);
        }
        if fields.rows > request.row_budget {
            return Err(ProtocolError::RowBudgetExceeded);
        }
        if stream.expected_rows.is_some_and(|rows| rows != fields.rows) {
            return Err(ProtocolError::OutputShape);
        }
        let digest = *stream.result_digest.clone().finalize().as_bytes();
        let mut expected = transport_receipt(
            &self.authority,
            request.request_digest,
            fields.correlation_nonce,
            fields.rows,
            digest,
        );
        let matches = expected.ct_eq(&fields.execution_receipt).unwrap_u8() == 1;
        expected.zeroize();
        if !matches {
            return Err(ProtocolError::ReceiptMismatch);
        }
        self.requests.remove(&fields.correlation_nonce);
        Ok(())
    }

    fn require_feature(&self, feature: u32) -> Result<(), ProtocolError> {
        let negotiated = self.negotiated.ok_or(ProtocolError::ConnectionState)?;
        if negotiated.features & feature == 0 {
            return Err(ProtocolError::FeatureNotNegotiated);
        }
        Ok(())
    }

    fn outbound_direction(&self) -> TransportDirection {
        match self.role {
            TransportRole::Client => TransportDirection::ClientToServer,
            TransportRole::Server => TransportDirection::ServerToClient,
        }
    }

    fn inbound_direction(&self) -> TransportDirection {
        match self.role {
            TransportRole::Client => TransportDirection::ServerToClient,
            TransportRole::Server => TransportDirection::ClientToServer,
        }
    }
}

impl RequestRecord {
    fn cancel_requested(&self) -> bool {
        match self.state {
            RequestState::Pending { cancel_requested } => cancel_requested,
            RequestState::Streaming(ref stream) => stream.cancel_requested,
        }
    }
}

impl TransportFields {
    fn maximum_frame_bytes(self) -> u32 {
        self.auxiliary
    }
}

fn parse_offer(fields: TransportFields, payload: &[u8]) -> Result<Offer, ProtocolError> {
    let offer = Offer {
        minimum_major: get_u16(payload, 0)?,
        maximum_major: get_u16(payload, 2)?,
        features: fields.features,
        maximum_frame_bytes: fields.auxiliary,
        maximum_chunk_bytes: get_u32(payload, 4)?,
    };
    if offer.maximum_frame_bytes < transport_frame_bytes(payload.len())? as u32 {
        return Err(ProtocolError::TransportConfiguration);
    }
    Ok(offer)
}

fn transport_receipt(
    authority: &Authority,
    request_digest: [u8; 32],
    nonce: u64,
    rows: u32,
    result_digest: [u8; 32],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new_keyed(&authority.receipt_key);
    digest.update(TRANSPORT_RECEIPT_DOMAIN);
    digest.update(&authority.context_digest);
    digest.update(&request_digest);
    digest.update(&nonce.to_le_bytes());
    digest.update(&rows.to_le_bytes());
    digest.update(&result_digest);
    let output = *digest.finalize().as_bytes();
    digest.zeroize();
    output
}

fn get_u16(bytes: &[u8], offset: usize) -> Result<u16, ProtocolError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(ProtocolError::LengthMismatch)?;
    Ok(u16::from_le_bytes(value.try_into().expect("checked width")))
}

fn get_u32(bytes: &[u8], offset: usize) -> Result<u32, ProtocolError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(ProtocolError::LengthMismatch)?;
    Ok(u32::from_le_bytes(value.try_into().expect("checked width")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{digest_label, AuthorityContext, BackendIdentity};

    const NOW: u64 = 1_000_000;
    const MAXIMUM_FRAME_BYTES: u32 = 4096;
    const MAXIMUM_CHUNK_BYTES: u32 = 1024;

    fn authority() -> Authority {
        let backend = BackendIdentity::new(
            1,
            2,
            digest_label(b"schema", b"connection"),
            digest_label(b"policy", b"connection"),
            digest_label(b"plan", b"connection"),
        )
        .expect("backend");
        let context = AuthorityContext::new(
            [1; 16],
            [2; 16],
            3,
            digest_label(b"capability", b"connection"),
            backend,
        )
        .expect("context");
        Authority::new_read([7; 32], 8, 9, 2_000_000, context).expect("authority")
    }

    fn pair(features: u32) -> (TransportConnection, TransportConnection) {
        let authority = authority();
        let config = TransportConfig::new(features, MAXIMUM_FRAME_BYTES, MAXIMUM_CHUNK_BYTES, 4)
            .expect("config");
        let mut client = TransportConnection::new(authority.clone(), TransportRole::Client, config);
        let mut server = TransportConnection::new(authority, TransportRole::Server, config);
        transfer(
            &mut client,
            &mut server,
            TransportKind::Hello,
            TransportFields {
                features,
                auxiliary: MAXIMUM_FRAME_BYTES,
                ..TransportFields::empty()
            },
            &negotiation_payload(2, 2, MAXIMUM_CHUNK_BYTES),
        )
        .expect("hello");
        transfer(
            &mut server,
            &mut client,
            TransportKind::Accept,
            TransportFields {
                features,
                auxiliary: MAXIMUM_FRAME_BYTES,
                ..TransportFields::empty()
            },
            &negotiation_payload(2, 0, MAXIMUM_CHUNK_BYTES),
        )
        .expect("accept");
        (client, server)
    }

    fn transfer(
        sender: &mut TransportConnection,
        receiver: &mut TransportConnection,
        kind: TransportKind,
        fields: TransportFields,
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        let mut frame = vec![0; transport_frame_bytes(payload.len())?];
        sender.encode(kind, fields, payload, &mut frame)?;
        receiver.decode(&frame, NOW)?;
        Ok(())
    }

    fn negotiation_payload(first: u16, second: u16, maximum_chunk: u32) -> Vec<u8> {
        let mut output = Vec::with_capacity(NEGOTIATION_PAYLOAD_BYTES);
        output.extend_from_slice(&first.to_le_bytes());
        output.extend_from_slice(&second.to_le_bytes());
        output.extend_from_slice(&maximum_chunk.to_le_bytes());
        output
    }

    fn register_pair(
        client: &mut TransportConnection,
        server: &mut TransportConnection,
        nonce: u64,
        result_budget: u32,
    ) {
        let operation = crate::Operation::new(1, 2, 3, 4, 5, 6).expect("operation");
        let mut encoder = crate::ClientSession::resume(authority(), nonce - 1).expect("encoder");
        let request = encoder
            .encode(operation, result_budget, 8, 1_500_000)
            .expect("request");
        let client_request = client
            .register_v1_request(&request)
            .expect("client request");
        let server_request = server
            .register_v1_request(&request)
            .expect("server request");
        assert_eq!(client_request, server_request);
        assert_eq!(client_request.nonce, nonce);
        assert_eq!(client_request.result_shape, 3);
    }

    #[test]
    fn negotiation_pins_the_offered_subset_and_limits() {
        let authority = authority();
        let config = TransportConfig::new(
            FEATURE_STREAMING,
            MAXIMUM_FRAME_BYTES,
            MAXIMUM_CHUNK_BYTES,
            4,
        )
        .expect("config");
        let mut client = TransportConnection::new(authority.clone(), TransportRole::Client, config);
        let mut server = TransportConnection::new(authority, TransportRole::Server, config);
        transfer(
            &mut client,
            &mut server,
            TransportKind::Hello,
            TransportFields {
                features: FEATURE_STREAMING,
                auxiliary: MAXIMUM_FRAME_BYTES,
                ..TransportFields::empty()
            },
            &negotiation_payload(2, 2, MAXIMUM_CHUNK_BYTES),
        )
        .expect("hello");

        let mut output = [0xa5; 168];
        assert_eq!(
            server.encode(
                TransportKind::Accept,
                TransportFields {
                    features: FEATURE_CANCELLATION,
                    auxiliary: MAXIMUM_FRAME_BYTES,
                    ..TransportFields::empty()
                },
                &negotiation_payload(2, 0, MAXIMUM_CHUNK_BYTES),
                &mut output,
            ),
            Err(ProtocolError::ConnectionState)
        );
        assert!(output.iter().all(|byte| *byte == 0));
        assert_eq!(server.phase(), TransportPhase::HelloReceived);
    }

    #[test]
    fn a_complete_result_requires_the_exact_incremental_receipt() {
        let (mut client, mut server) = pair(0);
        register_pair(&mut client, &mut server, 1, 16);
        let result = b"exact-result";
        let receipt = server.result_receipt(1, 2, result).expect("receipt");
        transfer(
            &mut server,
            &mut client,
            TransportKind::Result,
            TransportFields {
                correlation_nonce: 1,
                rows: 2,
                result_shape: 3,
                execution_receipt: receipt,
                ..TransportFields::empty()
            },
            result,
        )
        .expect("result");
        assert_eq!(
            client.result_receipt(1, 2, result),
            Err(ProtocolError::UnknownCorrelation)
        );
        assert_eq!(
            server.result_receipt(1, 2, result),
            Err(ProtocolError::UnknownCorrelation)
        );
    }

    #[test]
    fn streaming_enforces_sequence_budget_and_chunk_independent_receipts() {
        let (mut client, mut server) = pair(FEATURE_STREAMING);
        register_pair(&mut client, &mut server, 1, 6);
        transfer(
            &mut server,
            &mut client,
            TransportKind::StreamStart,
            TransportFields {
                correlation_nonce: 1,
                rows: u32::MAX,
                result_shape: 3,
                ..TransportFields::empty()
            },
            &[],
        )
        .expect("stream start");

        let mut refused = vec![0xa5; transport_frame_bytes(3).expect("length")];
        assert_eq!(
            server.encode(
                TransportKind::StreamChunk,
                TransportFields {
                    correlation_nonce: 1,
                    sequence: 2,
                    ..TransportFields::empty()
                },
                b"abc",
                &mut refused,
            ),
            Err(ProtocolError::SequenceMismatch)
        );
        assert!(refused.iter().all(|byte| *byte == 0));

        for (sequence, chunk) in [(1, b"abc".as_slice()), (2, b"def".as_slice())] {
            transfer(
                &mut server,
                &mut client,
                TransportKind::StreamChunk,
                TransportFields {
                    correlation_nonce: 1,
                    sequence,
                    ..TransportFields::empty()
                },
                chunk,
            )
            .expect("stream chunk");
        }
        let stream_receipt = server.stream_receipt(1, 2).expect("stream receipt");
        assert_eq!(
            stream_receipt,
            server
                .result_receipt(1, 2, b"abcdef")
                .expect("complete receipt")
        );
        transfer(
            &mut server,
            &mut client,
            TransportKind::StreamEnd,
            TransportFields {
                correlation_nonce: 1,
                sequence: 3,
                rows: 2,
                result_shape: 3,
                execution_receipt: stream_receipt,
                ..TransportFields::empty()
            },
            &[],
        )
        .expect("stream end");
    }

    #[test]
    fn cancellation_requires_a_request_and_an_accepted_cancel() {
        let (mut client, mut server) = pair(FEATURE_CANCELLATION);
        register_pair(&mut client, &mut server, 1, 16);

        let mut refused = [0xa5; 160];
        assert_eq!(
            server.encode(
                TransportKind::Error,
                TransportFields {
                    error_code: 7,
                    correlation_nonce: 1,
                    ..TransportFields::empty()
                },
                &[],
                &mut refused,
            ),
            Err(ProtocolError::ConnectionState)
        );
        assert!(refused.iter().all(|byte| *byte == 0));

        transfer(
            &mut client,
            &mut server,
            TransportKind::Cancel,
            TransportFields {
                correlation_nonce: 1,
                ..TransportFields::empty()
            },
            &[],
        )
        .expect("cancel");
        transfer(
            &mut server,
            &mut client,
            TransportKind::Error,
            TransportFields {
                error_code: 7,
                correlation_nonce: 1,
                ..TransportFields::empty()
            },
            &[],
        )
        .expect("cancel accepted");
    }

    #[test]
    fn an_invalid_receipt_never_reaches_the_client_state() {
        let (mut client, mut server) = pair(0);
        register_pair(&mut client, &mut server, 1, 16);
        let fields = TransportFields {
            correlation_nonce: 1,
            rows: 1,
            result_shape: 3,
            execution_receipt: [9; 32],
            ..TransportFields::empty()
        };
        let mut frame = [0; 163];
        encode_transport(
            &authority(),
            TransportDirection::ServerToClient,
            TransportKind::Result,
            fields,
            b"bad",
            &mut frame,
        )
        .expect("raw frame");
        assert_eq!(
            client.decode(&frame, NOW),
            Err(ProtocolError::ReceiptMismatch)
        );

        let receipt = server.result_receipt(1, 1, b"good").expect("receipt");
        transfer(
            &mut server,
            &mut client,
            TransportKind::Result,
            TransportFields {
                execution_receipt: receipt,
                ..fields
            },
            b"good",
        )
        .expect("valid result");
    }

    #[test]
    fn request_registration_authenticates_metadata_before_state_changes() {
        let (mut client, _) = pair(0);
        let operation = crate::Operation::new(1, 2, 3, 4, 5, 6).expect("operation");
        let mut request = crate::ClientSession::new(authority())
            .encode(operation, 16, 8, 1_500_000)
            .expect("request");
        request[60] ^= 1;
        assert_eq!(
            client.register_v1_request(&request),
            Err(ProtocolError::AuthenticationFailed)
        );

        request[60] ^= 1;
        assert_eq!(
            client.register_v1_request(&request).expect("registered"),
            RegisteredRequest {
                nonce: 1,
                result_shape: 3,
                result_budget: 16,
                row_budget: 8,
            }
        );
    }
}
