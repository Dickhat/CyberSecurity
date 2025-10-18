use iced::{widget::{column, button, container, text, text_input}, Task};
use postgres::{Client, NoTls};

use crate::algorithms::{streebog::streebog, to_hex};

#[derive(Debug, Clone)]
struct Credentials {
    login: String,
    password: String,
    access: bool,
    info_message: String
}

#[derive(Debug, Clone)]
enum Message {
    Login(Credentials),
    Registration(Credentials),
    RegistrationResult(bool),
    AnonAccess,
    Authorize(bool),
    Filling(Credentials),
    Error(String)
}

impl Credentials 
{
    fn new() -> Self {
        Self { login: "".to_string(), password: "".to_string(), access: false, info_message: "".to_string()}
    }

    // Обновляет состояние 
    fn update(&mut self, message: Message) -> iced::Task<Message>
    {
        match message {
            Message::Filling(credentials) => {self.login = credentials.login; self.password = credentials.password;},
            Message::Login(credentials) => return Task::perform(async move {auth_credential(credentials)},
                |result| {
                    match result {
                        Ok(auth_status) => {return Message::Authorize(auth_status);},
                        Err(message_err) => {return Message::Error(message_err);}
                    };
            }),
            Message::Registration(credentials) => return Task::perform(
                async move {reg_credential(credentials)}, |result| {Message::RegistrationResult(result)}),
            Message::AnonAccess => {self.login = String::from("Anon"); self.access = true;},
            Message::RegistrationResult(success) => {
                if success{self.info_message = "Пользователь успешно зарегистрирован. Авторизуйте по вашим данным.".to_string();}
                else {self.info_message = "Пользователь не зарегистрирован. Попробуйте снова".to_string();}
            },
            Message::Authorize(access) => {
                self.access = access;

                if !access {self.info_message = "Некорректные данные".to_string();}
            },
            Message::Error(err_message) => {self.info_message = err_message;}
        }

        iced::Task::none()
    }

    // Обновляет UI
    fn view(&self) -> iced::Element<'_, Message>
    {
        if self.access 
        {
            iced::widget::text(format!("User: {}", self.login)).into()
        }
        // Введение Логина и Пароля
        else {
            let greet_form = column![
                text(self.info_message.clone()),
                text_input("Login", &self.login).on_input({
                    move |login| Message::Filling(Credentials {
                        login,
                        password: self.password.clone(),
                        access: false,
                        info_message: "".to_string()
                    })
                })
                    .width(500),
                text_input("Password", &self.password).on_input({
                    move |password| Message::Filling(Credentials {
                        login: self.login.clone(),
                        password,
                        access: false,
                        info_message: "".to_string()
                    })
                })
                    .width(500),
                button("Log in")
                    .width(300)
                    .padding([10, 120])
                    .on_press(Message::Login(self.clone())),
                button("Register")
                    .width(300)
                    .padding([10, 120])
                    .on_press(Message::Registration(self.clone())),
                button("Anon access")
                    .width(300)
                    .padding([10, 100])
                    .on_press(Message::AnonAccess)
            ].align_x(iced::Alignment::Center);//.into()

            container(greet_form)
                                            .padding(100)
                                            .center(1600)
                                            .style(container::rounded_box)
                                            .into()
        }
    }
}

fn check_exist_user(login: &String, hash_password: &String) -> bool
{
    // Connect to the database.
    let mut client =
        Client::connect("host=localhost user=postgres password=postgres dbname=CyberSecurity" , NoTls).unwrap();

    // Запрос существования пользователя с текущими данными
    let row = client
        .query_one("SELECT COUNT(*) FROM public.users WHERE login = $1 AND password_hash = $2", &[&login, &hash_password])
        .unwrap();

    let count: i64 = row.get(0);

    if count != 0 {return true;} else {return false;}
}

/// Проверка, что пользователь ввел данные, существующие в БД
fn auth_credential(credentials:Credentials) -> Result<bool, String>
{
    if credentials.login == "" || credentials.password == "" {return Err("Логин или пароль не введены".to_string());}

    // Перевод в байты
    let pass_vec = credentials.password.as_bytes();

    // Получение Хэша пароля
    let hash_vec = streebog(&pass_vec[..], 512)?;
    let hash = to_hex(&hash_vec);
    
    Ok(check_exist_user(&credentials.login, &hash))
}

/// Попытка зарегистрировать нового пользователя
fn reg_credential(credentials:Credentials) -> bool
{
    if credentials.login == "" || credentials.password == "" {return false;}

    // Перевод в байты
    let pass_vec = credentials.password.as_bytes();

    // Получение Хэша пароля
    let hash_vec = match streebog(&pass_vec[..], 512)
    {
        Ok(hash) => hash,
        Err(_) => {return false;}
    };

    let hash = to_hex(&hash_vec);
    
    if check_exist_user(&credentials.login, &hash) {return false;}

    // Connect to the database.
    let mut client =
        Client::connect("host=localhost user=postgres password=postgres dbname=CyberSecurity" , NoTls).unwrap();

    match client.query_opt("INSERT INTO public.users (login, password_hash) VALUES($1, $2)", &[&credentials.login, &hash])
    {
        Ok(_) => true,
        Err(_) => false
    }
}

pub fn gui_start() -> iced::Result {
    // run the app from main function
    iced::application("Greetings", Credentials::update, Credentials::view)
        .run_with(|| (Credentials::new(), iced::Task::none()))
}