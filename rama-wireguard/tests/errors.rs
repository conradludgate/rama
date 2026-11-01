//! Public error composition and downcasting, without requiring socket I/O.
use rama_wireguard::{CryptoError, DeviceError, EngineError, ServiceError, TunnelServiceError};
use std::{error::Error, io};

#[test]
fn protocol_failures_keep_their_causes_through_the_service() {
    // This conversion lets applications use `?` with ordinary boxed errors.
    let error: Box<dyn Error + Send + Sync> = ServiceError::Engine(EngineError::Device(
        DeviceError::Crypto(CryptoError::Decryption),
    ))
    .into();
    let engine = error.source().unwrap();
    assert!(engine.is::<EngineError>());
    let device = engine.source().unwrap();
    assert!(device.is::<DeviceError>());
    let crypto = device.source().unwrap();
    assert_eq!(
        crypto.downcast_ref::<CryptoError>(),
        Some(&CryptoError::Decryption)
    );
    assert!(crypto.source().is_none());
    assert!(error.to_string().contains("authentication"));
}

#[test]
fn decoder_errors_can_be_reported_through_the_engine() {
    fn decode() -> Result<(), EngineError> {
        rama_wireguard::proto::Message::decode(&mut [])?;
        Ok(())
    }
    let error: Box<dyn Error> = decode().unwrap_err().into();
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<rama_wireguard::proto::DecodeError>(),
        Some(&rama_wireguard::proto::DecodeError::Truncated)
    );
}

#[test]
fn tunnel_handlers_preserve_application_errors() {
    let error = TunnelServiceError::Handler(io::Error::from(io::ErrorKind::BrokenPipe));
    let cause = error.source().unwrap().downcast_ref::<io::Error>().unwrap();
    assert_eq!(cause.kind(), io::ErrorKind::BrokenPipe);
}
