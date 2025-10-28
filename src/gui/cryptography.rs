use iced::{widget::{button, column, row, scrollable, text, text_input, text_editor, container}, Length::{self, Fill}, Task};
use crate::algorithms::streebog::streebog_string;

pub struct Cryptography {
    login: String,
    input_text: text_editor::Content,
    output_text: text_editor::Content,
    state: Message
}

#[derive(Debug, Clone)]
pub enum Message {
    Select,
    RSA,
    Streebog,
    StreebogInput(text_editor::Action),
    StreebogCompute,
    Kuznechick,
}

impl Cryptography {
    pub fn new(login: String) -> Self
    {
        Self
        {
            login, 
            input_text: text_editor::Content::new(), 
            output_text: text_editor::Content::new(),
            state: Message::Select
        }
    }

    pub fn update(&mut self, message: Message) -> iced::Task<Message>
    {
        match message {
            Message::Select => {

            },
            Message::RSA => {

            },
            Message::Streebog => {
                self.state = Message::Streebog;
            },
            Message::StreebogInput(content) => 
            {
                self.input_text.perform(content);
            },
            Message::StreebogCompute =>{
                let text = self.input_text.text();
                
                match streebog_string(text, 256) 
                {
                    Ok(res) => self.output_text = text_editor::Content::with_text(&res),
                    Err(err_message) => self.output_text = text_editor::Content::with_text(&err_message),
                }
            }
            Message::Kuznechick => {

            }
        }

        Task::none()
    }

    pub fn view(&self) -> iced::Element<'_, Message>
    {
        let mut column =  column![text(format!(" User: {}", self.login)).size(18)];
        column = column.push(iced::widget::horizontal_rule(2));

        match self.state
        {
            Message::Select => {
                column = column.push(row![
                        iced::widget::button(" RSA (Асимметричное шифрование)").on_press(Message::RSA),
                        iced::widget::button(" Streebog (Хэширование)").on_press(Message::Streebog),
                        iced::widget::button(" Kuznehcik (Блочное шифрование)").on_press(Message::Kuznechick)
                    ].spacing(10));

                column.spacing(5).into()
            },
            Message::Streebog => {
                column = column.push(row![
                            text_editor( &self.input_text)
                                .on_action(Message::StreebogInput)
                                .placeholder("Исходный текст, который необходимо захэшировать")
                                .wrapping(text::Wrapping::WordOrGlyph)
                                .height(500)
                                .padding(10),
                            button("Хэшировать").on_press(Message::StreebogCompute),
                            text_editor( &self.output_text)
                                .placeholder("Результат хэширования")
                            ]
                );

                column.spacing(5).into()
            },
            _ => {column.spacing(5).into()}
        }
    }
}