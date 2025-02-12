use anyhow::Result;
use qrcode::render::unicode;
use qrcode::QrCode;

pub fn data_to_qr<T: AsRef<[u8]>>(data: T) -> Result<String> {
    Ok(QrCode::new(data)?
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .build())
}
