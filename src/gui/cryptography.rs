use iced::{Length, Task, alignment::Horizontal, clipboard, widget::{button, center, column, row, text, text_editor, tooltip}};
use rfd;
use crate::algorithms::streebog::streebog_string;

use std::fs;

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
    CopyClipboard(String),
    PickFile,
    FileOpened(String)
}

const CUSTOM_FONT: iced::Font = iced::Font::with_name("fontello");

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
                self.state = Message::Select;
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
                
                if !text.is_empty() && text != "\n"
                {
                    match streebog_string(text, 256) 
                    {
                        Ok(res) => self.output_text = text_editor::Content::with_text(&res),
                        Err(err_message) => self.output_text = text_editor::Content::with_text(&err_message),
                    }
                }
            }
            Message::Kuznechick => {

            },
            Message::CopyClipboard(content) =>{
                return clipboard::write(content).map(|_: ()| Message::Streebog);
            },
            Message::PickFile => {
                return Task::perform(pick_file(), |content| {
                    match content {
                        Ok(text) => Message::FileOpened(text),
                        Err(_) => Message::Select
                    }
                });
            },
            Message::FileOpened(text) =>
            {
                self.input_text = text_editor::Content::with_text(&text);
            }
        }

        Task::none()
    }

    pub fn view(&self) -> iced::Element<'_, Message>
    {
        let mut column:iced::widget::Column<'_, Message> = column![];

        if let Message::Select = self.state
        {
            column = column.push(column![text(format!(" User: {}", self.login)).center().size(18)]);
        }
        else
        {
            column = column.push(
                column![
                    row![
                        tooltip(
                            button(text('\u{E80E}')
                                .font(CUSTOM_FONT))
                                .on_press(Message::Select),
                            text("Возврат к выбору алгоритмов"),
                            tooltip::Position::FollowCursor
                        ),
                        text(format!(" User: {}", self.login))
                            .size(18)
                            .align_x(Horizontal::Right)
                    ]
                ]
            );
        }

        column = column.push(iced::widget::horizontal_rule(2));

        match self.state
        {
            Message::Select => {
                column = column.push(
                    column![
                        text("Выберите один из алгоритмов предложенных ниже")
                            .size(24)
                            .width(Length::Fill)
                            .align_x(iced::alignment::Horizontal::Center),
                        row![
                            text("").width(Length::Fill),
                            button(" RSA (Асимметричное шифрование)").on_press(Message::RSA),
                            button(" Streebog (Хэширование)").on_press(Message::Streebog),
                            button(" Kuznehcik (Блочное шифрование)").on_press(Message::Kuznechick),
                            text("").width(Length::Fill),
                        ].spacing(10)
                    ].spacing(20));
                column.spacing(5).into()
            },
            Message::Streebog => {
                column = column.push(text("Хэширование алгоритмом Стрибог (ГОСТ Р 34.11-2018)")
                            .size(24)
                            .width(Length::Fill)
                            .align_x(iced::alignment::Horizontal::Center));
                column = column.push(
                    row![
                            column![      
                                row![
                                    tooltip(
                                        button(text('\u{E806}')
                                            .font(CUSTOM_FONT))
                                            .on_press(Message::PickFile),
                                        text("Выбор файла для хэширования"),
                                        tooltip::Position::FollowCursor
                                    ),
                                    tooltip(
                                        button(text('\u{E800}')
                                            .font(CUSTOM_FONT))
                                            .on_press(Message::CopyClipboard(self.input_text.text())),
                                        text(" Скопировать текст"),
                                        tooltip::Position::FollowCursor
                                    )
                                ],           
                                text("Исходный текст"),
                                text_editor(&self.input_text)
                                    .on_action(Message::StreebogInput)
                                    .placeholder("Исходный текст, который необходимо захэшировать")
                                    .wrapping(text::Wrapping::WordOrGlyph)
                                    .height(1000)
                                    .padding(10)
                            ],
                            center(column![
                                button("Хэшировать")
                                    .on_press(Message::StreebogCompute)
                                    .padding(30)
                            ]),
                            column![
                                row![
                                    tooltip(
                                        button(text('\u{E800}')
                                            .font(CUSTOM_FONT))
                                            .on_press(Message::CopyClipboard(self.output_text.text())),
                                        text(" Скопировать Хэш"),
                                        tooltip::Position::FollowCursor
                                    )
                                ],
                                text("Результат Хэширования"),
                                text_editor( &self.output_text)
                                    .placeholder("Результат хэширования")
                                    .wrapping(text::Wrapping::WordOrGlyph)
                                    .height(1000)
                                    .padding(10) 
                            ]
                        ]
                );

                column.spacing(20).into()
            },
            _ => {column.spacing(5).into()}
        }
    }
}

async fn pick_file() -> Result<String, String>
{
    let handle = rfd::AsyncFileDialog::new()
        .set_title(" Choose a file...")
        .pick_file()
        .await;

    match handle {
        Some(file) => return Ok(fs::read_to_string(file.path()).unwrap()),
        None => return Err("File not open".to_string()),
    };
}