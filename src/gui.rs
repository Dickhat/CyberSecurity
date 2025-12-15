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

pub fn button_style_rsa(status: iced::widget::button::Status) -> iced::widget::button::Style {
    let background = match status {
        iced::widget::button::Status::Hovered => iced::Color::from_rgb8(87, 157, 1),
        _ => iced::Color::from_rgb8(211, 254, 159)//iced::Color::from_rgb8(153, 204, 255),
    };

    iced::widget::button::Style {
        background: Some(iced::Background::Color(background)),
        text_color: iced::Color::BLACK,
        border: iced::Border::default(),
        shadow: iced::Shadow::default(),
    }
}

pub fn button_style_streebog(status: iced::widget::button::Status) -> iced::widget::button::Style {
    let background = match status {
        iced::widget::button::Status::Hovered => iced::Color::from_rgb8(255, 165, 0),
        _ => iced::Color::from_rgb8(255, 201, 102)//iced::Color::from_rgb8(153, 204, 255),
    };

    iced::widget::button::Style {
        background: Some(iced::Background::Color(background)),
        text_color: iced::Color::BLACK,
        border: iced::Border::default(),
        shadow: iced::Shadow::default(),
    }
}

pub fn button_style_kuznechik(status: iced::widget::button::Status) -> iced::widget::button::Style {
    let background = match status {
        iced::widget::button::Status::Hovered => iced::Color::from_rgb8(200, 65, 83),
        _ => iced::Color::from_rgb8(210, 144, 155)//iced::Color::from_rgb8(223, 144, 155),
    };

    iced::widget::button::Style {
        background: Some(iced::Background::Color(background)),
        text_color: iced::Color::BLACK,
        border: iced::Border::default(),
        shadow: iced::Shadow::default(),
    }
}

pub fn backward_button_style(status: iced::widget::button::Status) -> iced::widget::button::Style {
    let background = match status {
        iced::widget::button::Status::Hovered => iced::Color::from_rgb8(53, 212, 160),
        _ => iced::Color::from_rgb8(96, 212, 174)//iced::Color::from_rgb8(153, 204, 255),
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

pub fn text_editor_style_write() -> iced::widget::text_editor::Style
{
    iced::widget::text_editor::Style { 
        background: iced::Background::Color(iced::Color::WHITE), 
        border: iced::Border {
            color: iced::Color::BLACK,
            width: 1.0,
            radius: iced::border::Radius::default()
        }, 
        icon: iced::Color::TRANSPARENT, 
        placeholder: iced::Color::BLACK, 
        value: iced::Color::BLACK, 
        selection:iced::Color::from_rgb8(102, 102, 255)
    }                             
}

pub fn text_editor_style_read() -> iced::widget::text_editor::Style
{
    iced::widget::text_editor::Style { 
        background: iced::Background::Color(iced::Color::from_rgb8(224, 224, 224)), 
        border: iced::Border {
            color: iced::Color::BLACK,
            width: 1.0,
            radius: iced::border::Radius::default()
        }, 
        icon: iced::Color::TRANSPARENT, 
        placeholder: iced::Color::BLACK, 
        value: iced::Color::BLACK, 
        selection:iced::Color::from_rgb8(102, 102, 255)
    }                             
}

pub fn combo_box_input_style() -> iced::widget::text_input::Style
{
    iced::widget::text_input::Style { 
        background: iced::Background::Color(iced::Color::WHITE), 
        border: iced::Border {
            color: iced::Color::BLACK,
            width: 1.0,
            radius: iced::border::Radius::default()
        }, 
        icon: iced::Color::TRANSPARENT, 
        placeholder: iced::Color::BLACK, 
        value: iced::Color::BLACK, 
        selection:iced::Color::from_rgb8(102, 102, 255)
    }      
}

pub fn combo_box_menu_style() -> iced::overlay::menu::Style
{
    iced::overlay::menu::Style {
        background: iced::Color::from_rgb8(210, 144, 155).into(),
        border: iced::Border {
            color: iced::Color::BLACK,
            width: 1.0,
            radius: iced::border::Radius::default()
        },
        text_color: iced::Color::BLACK,
        selected_text_color: iced::Color::BLACK,
        selected_background: iced::Color::from_rgb8(200, 65, 83).into()
    } 
}