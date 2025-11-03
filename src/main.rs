mod gui;
mod algorithms;

use iced::{Settings, Task, window};
use gui::GUI;

use crate::gui::greet_screen;
use crate::gui::greet_screen::Credentials;
use crate::gui::cryptography;
use crate::gui::cryptography::Cryptography;

pub struct App 
{
    screen: GUI
}

#[derive(Debug, Clone)]
enum Message {
    Autorhization(greet_screen::Message),
    Cryptography(cryptography::Message),
}

impl App 
{
    fn new() -> Self
    {
        Self { 
            screen: GUI::Autorhization(Credentials::new())
        }
    }

    fn update(&mut self, message: Message) -> iced::Task<Message>
    {
        match message {
            Message::Autorhization(message) => {
                if let GUI::Autorhization(credentials) = &mut self.screen
                {
                    if credentials.access == true
                    {
                        self.screen = GUI::Cryptography(Cryptography::new(credentials.login.clone()));
                        return Task::done(Message::Cryptography(cryptography::Message::Select));
                    }

                    let task = credentials.update(message);
                    return task.map(Message::Autorhization);
                }
            },
            Message::Cryptography(message) => {
                if let GUI::Cryptography(crypt) = &mut self.screen
                {
                    let task = crypt.update(message);
                    return  task.map(Message::Cryptography);
                }
            }
        }

        iced::Task::none()
    }

    fn view(&self) -> iced::Element<'_, Message>
    {
        match &self.screen {
            GUI::Autorhization(credentials) => credentials.view().map(Message::Autorhization),
            GUI::Cryptography(crypt) => crypt.view().map(Message::Cryptography)
        }
    }
}

fn main() -> iced::Result {
    const ICON_BYTES: &[u8] = include_bytes!("gui/assets/papich3.ico");
    let icon = window::icon::from_file_data(ICON_BYTES, None).unwrap();

    // Параметры окна при запуске
    let window = window::Settings {
                size: iced::Size{width: 800.0, height: 600.0},
                resizable: true,
                decorations: true,
                icon: Some(icon),
                ..Default::default()
    };

    // run the app from main function
    iced::application("Greetings", App::update, App::view)
        .settings(Settings {
            fonts: vec![include_bytes!("gui/assets/fontello.ttf").as_slice().into()],
            ..Default::default()
        })
        .window(window)
        .theme(|_s| iced::Theme::CatppuccinMocha)
        .run_with(|| (App::new(), iced::Task::none()))
}

// Dark, Nord, SolarizedLight, GruvboxDark, TokyoNight, TokyoNightStorm, TokyoNightLight
// CatppuccinLatte, CatppuccinFrappe, CatppuccinMacchiato, CatppuccinMocha
// KanagawaWave, KanagawaDragon, Oxocarbon, 