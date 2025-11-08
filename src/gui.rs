pub mod greet_screen;
pub mod cryptography;

use greet_screen::Credentials;
use cryptography::Cryptography;

pub enum GUI 
{
    Autorhization(Credentials),
    Cryptography(Cryptography)
}

pub fn button_style(status: iced::widget::button::Status) -> iced::widget::button::Style {
    let background = match status {
        iced::widget::button::Status::Hovered => iced::Color::from_rgb8(102, 178, 255),
        _ => iced::Color::from_rgb8(153, 204, 255),
    };

    iced::widget::button::Style {
        background: Some(iced::Background::Color(background)),
        text_color: iced::Color::BLACK,
        border: iced::Border::default(),
        shadow: iced::Shadow::default(),
    }
}

pub fn text_editor_style() -> iced::widget::text_editor::Style
{
    iced::widget::text_editor::Style { 
        background: iced::Background::Color(iced::Color::TRANSPARENT), 
        border: iced::Border {
            color: iced::Color::from_rgba8(160, 160, 160, 1.0),
            width: 1.0,
            radius: iced::border::Radius::default()
        }, 
        icon: iced::Color::TRANSPARENT, 
        placeholder: iced::Color::from_rgba8(160, 160, 160, 1.0), 
        value: iced::Color::BLACK, 
        selection: iced::Color::TRANSPARENT
    }                             
}
