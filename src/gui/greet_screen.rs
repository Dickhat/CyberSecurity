use iced::{
    Length, Task, widget::{button, column, container, text, text_input}
};
use postgres::{Client, NoTls};
use crate::algorithms::{streebog::streebog, to_hex};
use crate::gui::{button_style, text_input_style};

#[derive(Debug, Clone)]
pub struct Credentials {
    pub login: String,
    password: String,
    pub access: bool,
    info_message: String,
    error_message: String
}

#[derive(Debug, Clone)]
pub enum Message {
    Login(Credentials),
    Registration(Credentials),
    RegistrationResult(bool),
    AnonAccess,
    Authorize(bool),
    Filling(Credentials),
    Error(String),
}

impl Credentials {
    pub fn new() -> Self {
        Self {
            login: "".to_string(),
            password: "".to_string(),
            access: false,
            info_message: String::new(),
            error_message: String::new()
        }
    }

    // Обновляет состояние
    pub fn update(&mut self, message: Message) -> iced::Task<Message> {
        match message {
            Message::Filling(credentials) => {
                self.login = credentials.login;
                self.password = credentials.password;
            }
            Message::Login(credentials) => {
                return Task::perform(async move { auth_credential(credentials) }, |result| {
                    match result {
                        Ok(auth_status) => {
                            return Message::Authorize(auth_status);
                        }
                        Err(message_err) => {
                            return Message::Error(message_err);
                        }
                    };
                })
            }
            Message::Registration(credentials) => {
                return Task::perform(async move { reg_credential(credentials) }, |result| {
                    Message::RegistrationResult(result)
                })
            }
            Message::AnonAccess => {
                self.login = String::from("Anon");
                self.access = true;
                return Task::done(Message::Authorize(true));
            }
            Message::RegistrationResult(success) => {
                if success {
                    self.info_message =
                        "Пользователь успешно зарегистрирован. Авторизуйте по вашим данным."
                            .to_string();
                } else {
                    self.info_message = String::new();
                    self.error_message = "Пользователь не зарегистрирован. Попробуйте снова".to_string();
                    return iced::Task::none();
                }
            }
            Message::Authorize(access) => {
                self.access = access;

                if !access {
                    self.error_message = "Некорректные данные".to_string();
                    self.info_message = String::new();
                    return iced::Task::none();
                }
            }
            Message::Error(err_message) => {
                self.info_message = String::new();
                self.error_message = err_message;
                return iced::Task::none();
            }
        }

        self.error_message = String::new();
        iced::Task::none()
    }

    // Обновляет UI
    pub fn view(&self) -> iced::Element<'_, Message> {
        let greet_form = column![
                column![
                    text("CyberSecure")
                        .size(36)
                ].width(500)
                 .padding([10, 30])
                 .align_x(iced::Alignment::Center),
                column![
                    text(self.info_message.clone()),
                    text(self.error_message.clone())
                        .color(iced::Color::from_rgb(1.0, 0.0, 0.0)),
                    text_input("Логин", &self.login)
                        .on_input({
                            move |login| {
                                Message::Filling(Credentials {
                                    login,
                                    password: self.password.clone(),
                                    access: false,
                                    info_message: String::new(),
                                    error_message: String::new()
                                })
                            }
                        })
                        .style(|_theme, _status| text_input_style())
                        .width(500),
                    text_input("Пароль", &self.password)
                        .on_input({
                            move |password| {
                                Message::Filling(Credentials {
                                    login: self.login.clone(),
                                    password,
                                    access: false,
                                    info_message: String::new(),
                                    error_message: String::new()
                                })
                            }
                        })
                        .style(|_theme, _status| text_input_style())
                        .width(500),
                    button("Авторизоваться")
                        .width(320)
                        .style(|_theme, status| button_style(status))
                        .padding([10, 70])
                        .on_press(Message::Login(self.clone())),
                    button("Зарегистрироваться")
                        .width(320)
                        .style(|_theme, status| button_style(status))
                        .padding([10, 70])
                        .on_press(Message::Registration(self.clone())),
                    button("Анонимный доступ")
                        .style(|_theme, status| button_style(status))
                        .width(320)
                        .padding([10, 70])
                        .on_press(Message::AnonAccess)
                ].spacing(15).align_x(iced::Alignment::Center)
            ].spacing(15);

        container(greet_form)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }
}

fn check_exist_user(login: &String, hash_password: &String) -> bool {
    // Connect to the database.
    let mut client = Client::connect(
        "host=localhost user=postgres password=postgres dbname=CyberSecurity",
        NoTls,
    )
    .unwrap();

    // Запрос существования пользователя с текущими данными
    let row = client
        .query_one(
            "SELECT COUNT(*) FROM public.users WHERE login = $1 AND password_hash = $2",
            &[&login, &hash_password],
        )
        .unwrap();

    let count: i64 = row.get(0);

    if count != 0 {
        return true;
    } else {
        return false;
    }
}

/// Проверка, что пользователь ввел данные, существующие в БД
fn auth_credential(credentials: Credentials) -> Result<bool, String> {
    if credentials.login == "" || credentials.password == "" {
        return Err("Логин или пароль не введены".to_string());
    }

    // Перевод в байты
    let pass_vec = credentials.password.as_bytes();

    // Получение Хэша пароля
    let hash_vec = streebog(&pass_vec[..], 512)?;
    let hash = to_hex(&hash_vec);

    Ok(check_exist_user(&credentials.login, &hash))
}

/// Попытка зарегистрировать нового пользователя
fn reg_credential(credentials: Credentials) -> bool {
    if credentials.login == "" || credentials.password == "" {
        return false;
    }

    // Перевод в байты
    let pass_vec = credentials.password.as_bytes();

    // Получение Хэша пароля
    let hash_vec = match streebog(&pass_vec[..], 512) {
        Ok(hash) => hash,
        Err(_) => {
            return false;
        }
    };

    let hash = to_hex(&hash_vec);

    if check_exist_user(&credentials.login, &hash) {
        return false;
    }

    // Connect to the database.
    let mut client = Client::connect(
        "host=localhost user=postgres password=postgres dbname=CyberSecurity",
        NoTls,
    )
    .unwrap();

    match client.query_opt(
        "INSERT INTO public.users (login, password_hash) VALUES($1, $2)",
        &[&credentials.login, &hash],
    ) {
        Ok(_) => true,
        Err(_) => false,
    }
}