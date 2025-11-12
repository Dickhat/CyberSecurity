pub mod greet_screen;
pub mod cryptography;

use greet_screen::Credentials;
use cryptography::Cryptography;
use iced::{Background, Border, Color, border::Radius};

pub enum GUI 
{
    Autorhization(Credentials),
    Cryptography(Cryptography)
}

pub fn button_style(status: iced::widget::button::Status) -> iced::widget::button::Style {
    let background = match status {
        iced::widget::button::Status::Hovered => iced::Color::from_rgb8(102, 178, 255),
        _ => iced::Color::from_rgb8(204, 204, 255)//iced::Color::from_rgb8(153, 204, 255),
    };

    iced::widget::button::Style {
        background: Some(iced::Background::Color(background)),
        text_color: iced::Color::BLACK,
        border: iced::Border::default(),
        shadow: iced::Shadow::default(),
    }
}

pub fn text_input_style() -> iced::widget::text_input::Style
{
    iced::widget::text_input::Style {
        background: Background::Color(Color::TRANSPARENT),
        border: Border {
            color: Color::BLACK,
            width: 1.0,
            radius: Radius::default()
        },
        icon: Color::BLACK,
        placeholder: Color::BLACK,
        value: Color::BLACK,
        selection:iced::Color::from_rgb8(102, 102, 255)
    }
}

pub fn text_editor_style() -> iced::widget::text_editor::Style
{
    iced::widget::text_editor::Style { 
        background: iced::Background::Color(iced::Color::TRANSPARENT), 
        border: iced::Border {
            color: iced::Color::BLACK,
            width: 1.0,
            radius: iced::border::Radius::default()
        }, 
        icon: iced::Color::TRANSPARENT, 
        placeholder: iced::Color::BLACK, 
        value: iced::Color::BLACK, 
        selection: iced::Color::TRANSPARENT
    }                             
}
