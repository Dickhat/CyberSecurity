use iced::{Length, Task, alignment::Horizontal, clipboard, widget::{button, center, column, row, text, text_editor, text_editor::Content, tooltip}};
use rfd;

use std::fmt::Write;
use std::fs;

use crate::algorithms::to_hex;
use crate::algorithms::streebog::streebog_string;
use crate::algorithms::kuznechik::Kuznechik;

pub struct Cryptography {
    login: String,
    input_text: text_editor::Content,
    output_text: text_editor::Content,
    state: Message,
    keys_kuznechik: Kuznechik,
    keys_kuznechik_text: text_editor::Content,
    error: String
}

#[derive(Debug, Clone)]
pub enum Message {
    Select,
    RSA,
    CurrentState,
    Streebog,
    StreebogInput(text_editor::Action),
    StreebogCompute,
    Kuznechick,
    KuznechickKeys,
    KuznechickKeysLoad,
    KuznechickKeysSave,
    KuznechickKeysGenerate,
    KuznechickEncryption,
    KuznechickDecryption,
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
            state: Message::Select,
            keys_kuznechik: Kuznechik { keys: (Vec::new(), vec![[0u8; 16]; 10]) },
            keys_kuznechik_text: text_editor::Content::new(),
            error: String::new()
        }
    }

    // Перевод ключей в строку для отображения в GUI
    fn keys_to_string(&self) -> Result<String, String>
    {
        // Формирование String из ключей
        let mut text:String = String::new();

        match writeln!(text, "K = {}", to_hex(&self.keys_kuznechik.keys.0)) {
            Ok(_) => {},
            Err(_) => {return Err("Ошибка отображения ключей в интерфейсе".to_string());}
        };

        // Запись всех итерационных ключей в файл
        for idx in 0..self.keys_kuznechik.keys.1.len() {
            match writeln!(text, "K{} = {}", idx + 1, to_hex(&self.keys_kuznechik.keys.1[idx])) {
                Ok(_) => {},
                Err(_) => {return Err("Ошибка отображения ключей в интерфейсе".to_string());}
            };
        }

        return Ok(text);
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
            Message::StreebogInput(content) => {
                self.input_text.perform(content);
            },
            Message::StreebogCompute => {
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
                self.state = Message::Kuznechick;
            },
            Message::KuznechickKeys => {
                self.state = Message::KuznechickKeys;
            },
            Message::KuznechickKeysLoad => {
                let path = match rfd::FileDialog::new()
                    .set_title(" Выберите файл с ключами для алгоритма Кузнечик...")
                    .pick_file()
                    {
                        Some(path_buf) => path_buf,
                        None => {
                            self.error = "Некорректный файл с ключами".to_string();
                            return Task::none();
                        }
                    };

                match Kuznechik::get_keys_from_file(&path)
                {
                    Ok(keys) => { 
                        self.keys_kuznechik = Kuznechik{keys}
                    },
                    Err(error) => {
                        self.error = error;
                        return Task::none();
                    }
                };

                // Для отображения в GUI
                match self.keys_to_string() {
                    Ok(res) => {
                        self.keys_kuznechik_text = Content::with_text(&res);
                    },
                    Err(error) => {
                        self.error = error;
                        return Task::none();
                    }
                };
            },
            Message::KuznechickKeysSave => {
                match rfd::FileDialog::new()
                    .set_title(" Сохранение файла с ключами...")
                    .save_file()
                    {
                        Some(path) => 
                            match self.keys_to_string()
                            {
                                Ok(res) => fs::write(path, res).unwrap(),
                                Err(_) => self.error = "Не удалось сохранить файл с ключами".to_string()
                            }
                        ,
                        None => self.error = "Не удалось сохранить файл с ключами".to_string()
                    }
                
                return Task::none();
            },
            Message::KuznechickKeysGenerate => {
                self.keys_kuznechik = Kuznechik { keys: Kuznechik::key_generate() };

                // Для отображения в GUI
                match self.keys_to_string() {
                    Ok(res) => {
                        self.keys_kuznechik_text = Content::with_text(&res);
                    },
                    Err(error) => {
                        self.error = error;
                        return Task::none();
                    }
                };
            },
            Message::KuznechickEncryption => {},
            Message::KuznechickDecryption => {},
            Message::CopyClipboard(content) =>{
                return clipboard::write(content).map(|_: ()| Message::CurrentState);
            },
            Message::PickFile => {
                return Task::perform(pick_file(), |content| {
                    match content {
                        Ok(text) => Message::FileOpened(text),
                        Err(_) => Message::CurrentState
                    }
                });
            },
            Message::FileOpened(text) =>
            {
                self.input_text = text_editor::Content::with_text(&text);
            },
            Message::CurrentState => {}
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
        // Отрисовывать кнопку "Возврат к опциям алгоритма Кузнечик"
        else if let Message::KuznechickKeys = self.state
        {
            column = column.push(
                column![
                    row![
                        tooltip(
                            button(text('\u{E80E}')
                                .font(CUSTOM_FONT))
                                .on_press(Message::Kuznechick),
                            text("Возврат к выбору опций алгоритма Кузнечик"),
                            tooltip::Position::Bottom
                        ),
                        text(format!(" User: {}", self.login))
                            .size(18)
                            .align_x(Horizontal::Right)
                    ]
                ]
            );
        }
        // Отрисовывать кнопку "Возврат к выбору алгоритмов"
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
                            tooltip::Position::Bottom
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
                column = column.spacing(5);
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
                                        tooltip::Position::Top
                                    ),
                                    tooltip(
                                        button(text('\u{E800}')
                                            .font(CUSTOM_FONT))
                                            .on_press(Message::CopyClipboard(self.input_text.text())),
                                        text(" Скопировать текст"),
                                        tooltip::Position::Top
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
                                        tooltip::Position::Top
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

                //column = column.spacing(20);
            },
            Message::Kuznechick => {
                column = column.push(column![
                    button("Управление криптографическими ключами алгоритма Кузнечик")
                        .on_press(Message::KuznechickKeys),
                    button("Шифрование алгоритмом Кузнечик")
                        .on_press(Message::KuznechickEncryption),
                    button("Расшифрование алгоритмом Кузнечик")
                        .on_press(Message::KuznechickDecryption)
                ].padding(10).spacing(10));
            },
            Message::KuznechickKeys => {
                column = column.push(text("Управление криптографическими ключами алгоритма Кузнечик (ГОСТ Р 34.12-2018)")
                            .size(24)
                            .width(Length::Fill)
                            .align_x(iced::alignment::Horizontal::Center));

                if !self.error.is_empty()
                {
                    column = column
                                .push(
                                    text("Ошибка: ".to_string() + &self.error.clone())
                                        .style(|_theme: &iced::Theme| iced::widget::text::Style {
                                            color: Some(iced::Color::from_rgb(1.0, 0.0, 0.0)), // красный цвет
                                        }));
                }

                column = column.push(
                    row![
                            column![      
                                row![
                                    tooltip(
                                        button(text('\u{E812}')
                                            .font(CUSTOM_FONT))
                                            .on_press(Message::KuznechickKeysLoad),
                                        text("Выбор файла для загрузки существующих ключей"),
                                        tooltip::Position::Top
                                    ),
                                    tooltip(
                                        button(text('\u{E800}')
                                            .font(CUSTOM_FONT))
                                            .on_press(Message::CopyClipboard(self.keys_kuznechik_text.text())),
                                        text(" Скопировать ключи в буфер обмена"),
                                        tooltip::Position::Top
                                    ),
                                    tooltip(
                                        button(text('\u{E813}')
                                            .font(CUSTOM_FONT))
                                            .on_press(Message::KuznechickKeysSave),
                                        text("Сохранить ключи в файл"), 
                                        tooltip::Position::Top
                                    ),
                                    button("Сгенерировать ключи")
                                        .on_press(Message::KuznechickKeysGenerate)
                                ],
                                text("Криптографические ключи"),
                                text_editor(&self.keys_kuznechik_text)
                                    .placeholder("Криптографические ключи для Кузнечика")
                                    .wrapping(text::Wrapping::WordOrGlyph)
                                    .height(1000)
                                    .padding(10)
                            ]]);
            }
            _ => {column = column.spacing(5);}
        }

        column.into()
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