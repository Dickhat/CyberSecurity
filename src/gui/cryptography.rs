use iced::{
    Length, Task, alignment::Horizontal, clipboard, 
    widget::{button, center, column, combo_box, row, text, text_editor, tooltip, container}};
use rfd;

use rand;
use std::{fmt::Write, str::from_utf8, fs, io::{BufRead, BufReader}, path::PathBuf};

use crate::algorithms::{self, to_hex, hex_to_bytes};
use crate::algorithms::streebog::streebog_string;
use crate::algorithms::kuznechik::Kuznechik;
use crate::algorithms::block_cipher_modes;
use crate::gui::{button_style, backward_button_style, text_editor_style};

pub struct Cryptography {
    // General data
    login: String,
    state: Message,

    // Информация по завершению операций
    topbar_info: String,    
    compute_info: String,

    // Информация об ошибках
    topbar_error: String,   // Ошибка, появляющаяся сверху у функциональных кнопок
    compute_error: String,  // Ошибка, появляющаяся при некорректной работе алгоритма

    // Streebog
    streebog_text: text_editor::Content,
    streebog_hash: text_editor::Content,

    // Kuznechik
    kuznechik_modes: combo_box::State<KuznechickModes>,
    current_mode: Option<KuznechickModes>,  
    keys_kuznechik: Kuznechik,
    mods_param: (u32, u32, Vec<u8>), // s(0 < s <= 128), z (целое от 1), IV - инициализирующий вектор
    kuzcnechik_text: text_editor::Content,
    keys_kuznechik_text: text_editor::Content
}

#[derive(Debug, Clone)]
pub enum KuznechickModes {
    ECB,
    CTR,
    OFB,
    CBC,
    CFB
    //MAC
}

impl std::fmt::Display for KuznechickModes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KuznechickModes::ECB => "ECB (Режим простой замены)",
            KuznechickModes::CTR => "CTR (Режим гаммирования)",
            KuznechickModes::OFB => "OFB (Режим гаммирования с обратной связью по выходу)",
            KuznechickModes::CBC => "CBC (Режим простой замены с зацеплением)",
            KuznechickModes::CFB => "CFB (Режим гаммирования с обратной связью по шифротексту)" 
            //KuznechickModes::MAC => "MAC",
        })
    }
}


#[derive(Debug, Clone)]
pub enum Message {
    Select,
    CurrentState,

    RSA,

    // Все состояния, связанные со Стрибогом
    Streebog,
    StreebogCompute,

    // Все состояния, связанные с Кузнечиком
    Kuznechick,
    KuznechickChangeMode(KuznechickModes),
    KuznechickSaveFile(String),

    KuznechickKeys,
    KuznechickKeysGenerate,
    KuznechickKeysLoad,
    KuznechickKeysSave,

    KuznechickEncryption,
    KuznechickEncryptionCompute,
    KuznechickDecryptionCompute,

    // Все состояния, связанные с побочными операциями
    InputTextEditor(text_editor::Action),
    CopyClipboard(String),
    PickFile
}

const CUSTOM_FONT: iced::Font = iced::Font::with_name("crypto-icons");

impl Cryptography {
    pub fn new(login: String) -> Self
    {
        Self
        {
            login, 
            state: Message::Select,
            topbar_info: String::new(),
            compute_info: String::new(),
            topbar_error: String::new(),
            compute_error: String::new(),

            streebog_text: text_editor::Content::new(), 
            streebog_hash: text_editor::Content::new(),

            keys_kuznechik: Kuznechik { keys: (Vec::new(), vec![[0u8; 16]; 10]) },
            kuznechik_modes: combo_box::State::new(vec![
                KuznechickModes::ECB,
                KuznechickModes::CTR,
                KuznechickModes::OFB,
                KuznechickModes::CBC,
                KuznechickModes::CFB
                //KuznechickModes::MAC
            ]),
            mods_param: (0, 0, Vec::new()),
            current_mode: None,
            kuzcnechik_text: text_editor::Content::new(),
            keys_kuznechik_text: text_editor::Content::new()
        }
    }

    // Сбрасывает все уведомления об ошибках и результатах операций 
    fn info_error_msg_reset(&mut self)
    {
        self.topbar_info = String::new();
        self.compute_info = String::new();
        self.topbar_error = String::new();
        self.compute_error = String::new();
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

        // Запись параметром алгоритмов S, M, IV
        match writeln!(text, "S = {}\nZ = {} \nIV = {}", self.mods_param.0, self.mods_param.1, to_hex(&self.mods_param.2)) {
            Ok(_) => {},
            Err(_) => {return Err("Ошибка отображения ключей в интерфейсе".to_string());}
        };
        
        return Ok(text);
    }
    
    fn get_keys_from_file(&self, path: &PathBuf) -> Result<(Vec<u8>, Vec<[u8; 16]>, u32, u32, Vec<u8>), String> {
        let file = match fs::File::open(path)
        {
            Ok(file) => file,
            Err(_) => {return Err("Ошибка открытия файла с ключами".to_string());}
        };

        let reader = BufReader::new(file);

        let mut main_key: Vec<u8> = Vec::new();
        let mut round_keys: Vec<[u8; 16]> = Vec::new();
        let mut s = 1;
        let mut z = 1;
        let mut iv = Vec::new();

        for line in reader.lines() {
            let line = match line 
            {
                Ok(line) => line,
                Err(_) => {return Err(" Некорректный файл с ключами".to_string());}
            };

            let parts: Vec<&str> = line.split('=').map(|s| s.trim()).collect();

            if parts.len() != 2
            {
                return Err(" Некорректный файл с ключами".to_string());
            }

            let name = parts[0];
            let value = parts[1];
            let mut bytes;

            if name == "K" {
                bytes = hex_to_bytes(value);
                bytes.reverse();
                
                main_key = bytes;
            } 
            else if name == "S"
            {
                s = match value.parse::<u32>() {
                    Ok(val) => val,
                    Err(_) => return Err("Ошибка распознавания файла с ключами".to_string())
                };
            } 
            else if name == "Z"
            {
                z = match value.parse::<u32>() {
                    Ok(val) => val,
                    Err(_) => return Err("Ошибка распознавания файла с ключами".to_string())
                };
            } 
            else if name == "IV"
            {
                bytes = hex_to_bytes(value);
                bytes.reverse();

                iv = bytes;
            }
            else {
                bytes = hex_to_bytes(value);
                bytes.reverse();

                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                round_keys.push(arr);
            }
        }

        if iv.is_empty() {return Err("Некорректный файл с ключами".to_string());}

        Ok((main_key, round_keys, s, z, iv))
    }

    pub fn update(&mut self, message: Message) -> iced::Task<Message>
    {
        match message {
            Message::Select => {
                self.state = Message::Select;
                self.info_error_msg_reset();
            },
            Message::RSA => {

            },
            Message::Streebog => {
                self.state = Message::Streebog; 
                self.info_error_msg_reset();
            },
            Message::StreebogCompute => {
                let text = self.streebog_text.text();
                self.info_error_msg_reset();

                if !text.is_empty() && text != "\n"
                {
                    match streebog_string(text, 256) 
                    {
                        Ok(res) => self.streebog_hash = text_editor::Content::with_text(&res),
                        Err(message) => self.compute_error = message
                    };
                }
            }
            Message::Kuznechick => {
                self.state = Message::Kuznechick;
                self.info_error_msg_reset();
            },
            Message::KuznechickChangeMode(mode) => {
                self.current_mode = Some(mode);
                self.info_error_msg_reset();
            },
            Message::KuznechickSaveFile(text) => {
                self.info_error_msg_reset();
                
                match rfd::FileDialog::new()
                    .set_title(" Сохранение файла с текстом...")
                    .save_file()
                    {
                        Some(path) => {
                            match fs::write(&path, text) {
                                Ok(_) => self.topbar_info = format!("Результат записан в {}", path.display()),
                                Err(_) => self.topbar_error = "Не удалось сохранить файл текста".to_string(),
                            };
                        },
                        None => {
                            self.topbar_error = "Не удалось сохранить файл текста".to_string();
                        }
                };
            },
            Message::KuznechickKeys => {
                self.state = Message::KuznechickKeys;
                self.info_error_msg_reset();
            },
            Message::KuznechickKeysLoad => {
                self.info_error_msg_reset();

                let path = match rfd::FileDialog::new()
                    .set_title(" Выберите файл с ключами для алгоритма Кузнечик...")
                    .pick_file()
                    {
                        Some(path_buf) => path_buf,
                        None => {
                            self.topbar_error = "Некорректный файл с ключами".to_string();
                            return Task::none();
                        }
                    };

                match self.get_keys_from_file(&path)
                {
                    Ok(params) => { 
                        self.keys_kuznechik = Kuznechik{keys: (params.0, params.1)};
                        self.mods_param = (params.2, params.3, params.4)
                    },
                    Err(topbar_error) => {
                        self.topbar_error = topbar_error;
                        return Task::none();
                    }
                };

                // Для отображения в GUI
                match self.keys_to_string() {
                    Ok(res) => {
                        self.keys_kuznechik_text = text_editor::Content::with_text(&res);
                        self.topbar_info = format!("Ключи загружены из {}", path.display());
                    },
                    Err(topbar_error) => self.topbar_error = topbar_error
                };
            },
            Message::KuznechickKeysSave => {
                self.info_error_msg_reset();

                match rfd::FileDialog::new()
                    .set_title(" Сохранение файла с ключами...")
                    .save_file() {
                        Some(path) => {
                            match self.keys_to_string() {
                                Ok(res) => {
                                    match fs::write(&path, res) {
                                        Ok(_) => self.topbar_info = format!("Ключи записаны в {}", path.display()),
                                        Err(_) => self.topbar_error = "Не удалось сохранить ключи в файл".to_string(),
                                    };
                                }
                                Err(_) => self.topbar_error = "Не удалось сохранить файл с ключами".to_string()
                            };
                        },
                        None => self.topbar_error = "Не удалось сохранить файл с ключами".to_string()
                };
            },
            Message::KuznechickKeysGenerate => {
                self.info_error_msg_reset();
                self.keys_kuznechik = Kuznechik { keys: Kuznechik::key_generate() };

                let mut s= rand::random::<u32>() % 128;
                let z = rand::random::<u32>() % 13 + 1;

                if s < 8 {s += 11;}

                self.mods_param = (s, z, algorithms::random_vec((z * 16) as usize));

                // Для отображения в GUI
                match self.keys_to_string() {
                    Ok(res) => self.keys_kuznechik_text = text_editor::Content::with_text(&res),
                    Err(topbar_error) => self.topbar_error = topbar_error
                };
            },
            Message::KuznechickEncryption => {
                self.state = Message::KuznechickEncryption;
                self.info_error_msg_reset();
            },
            Message::KuznechickEncryptionCompute => {
                self.info_error_msg_reset();

                if self.keys_kuznechik.keys.0.is_empty() {
                    self.compute_error = "Ключи не были созданы".to_string();
                    return Task::none();
                }

                match self.current_mode 
                {
                    Some(KuznechickModes::CBC) => {
                        let output: Vec<[u8; 16]> = block_cipher_modes::CipherModes::ecb_encrypt(
                            &block_cipher_modes::CipherModes{keys: self.keys_kuznechik.clone()}, 
                            self.kuzcnechik_text.text().as_bytes()
                        );

                        let output_bytes: Vec<u8> = output.iter().flatten().copied().collect();

                        match rfd::FileDialog::new()
                            .set_title(" Сохранение файла с зашифрованными данными...")
                            .set_file_name("CBC")
                            .save_file()
                            {
                                Some(path) => {
                                    match fs::write(&path, output_bytes) {
                                        Ok(_) => self.compute_info = format!("Результат записан в {}", path.display()),
                                        Err(_) => self.compute_error = "Не удалось сохранить файл с зашифрованным текстом".to_string(),
                                    };
                                },
                                None => self.compute_error = "Не удалось сохранить файл с данными".to_string()
                        };
                    },
                    Some(KuznechickModes::CFB) => {
                        let output  = block_cipher_modes::CipherModes::cfb_encrypt(
                            &block_cipher_modes::CipherModes{keys: self.keys_kuznechik.clone()}, 
                            self.kuzcnechik_text.text().as_bytes(),
                            self.mods_param.0 as usize,
                            self.mods_param.1 as usize,
                            &self.mods_param.2
                        );

                        match rfd::FileDialog::new()
                            .set_title(" Сохранение файла с зашифрованными данными...")
                            .set_file_name("CFB")
                            .save_file()
                            {
                                Some(path) => {
                                    match fs::write(&path, output) {
                                        Ok(_) => self.compute_info = format!("Результат записан в {}", path.display()),
                                        Err(_) => self.compute_error = "Не удалось сохранить файл с зашифрованным текстом".to_string(),
                                    };
                                },
                                None => self.compute_error = "Не удалось сохранить файл с данными".to_string()
                        };
                    },
                    Some(KuznechickModes::CTR) => {
                        let mut iv:[u8; 8] = [0; 8];
                        iv.clone_from_slice(&self.mods_param.2[0..8]);

                        let output = block_cipher_modes::CipherModes::ctr_crypt(
                            &block_cipher_modes::CipherModes{keys: self.keys_kuznechik.clone()}, 
                            self.kuzcnechik_text.text().as_bytes(),
                            self.mods_param.0 as usize,
                            &iv
                        );

                        match rfd::FileDialog::new()
                            .set_title(" Сохранение файла с зашифрованными данными...")
                            .set_file_name("CTR")
                            .save_file()
                            {
                                Some(path) => {
                                    match fs::write(&path, output) {
                                        Ok(_) => self.compute_info = format!("Результат записан в {}", path.display()),
                                        Err(_) => self.compute_error = "Не удалось сохранить файл с зашифрованным текстом".to_string(),
                                    };
                                },
                                None => self.compute_error = "Не удалось сохранить файл с данными".to_string()
                        };
                    },
                    Some(KuznechickModes::ECB) => {
                        let output = block_cipher_modes::CipherModes::ecb_encrypt(
                            &block_cipher_modes::CipherModes{keys: self.keys_kuznechik.clone()}, 
                            self.kuzcnechik_text.text().as_bytes()
                        );

                        let bytes_output: Vec<u8> = output.iter().flatten().copied().collect();

                        match rfd::FileDialog::new()
                            .set_title(" Сохранение файла с зашифрованными данными...")
                            .set_file_name("ECB")
                            .save_file()
                            {
                                Some(path) => {
                                    match fs::write(&path, bytes_output) {
                                        Ok(_) => self.compute_info = format!("Результат записан в {}", path.display()),
                                        Err(_) => self.compute_error = "Не удалось сохранить файл с зашифрованным текстом".to_string(),
                                    };
                                },
                                None => self.compute_error = "Не удалось сохранить файл с данными".to_string()
                        };
                    },
                    Some(KuznechickModes::OFB) => {
                        let output = block_cipher_modes::CipherModes::ofb_crypt(
                            &block_cipher_modes::CipherModes{keys: self.keys_kuznechik.clone()}, 
                            self.kuzcnechik_text.text().as_bytes(),
                            self.mods_param.0 as usize,
                            self.mods_param.1 as usize,
                            &self.mods_param.2
                        );

                        match rfd::FileDialog::new()
                            .set_title(" Сохранение файла с зашифрованными данными...")
                            .set_file_name("OFB")
                            .save_file()
                            {
                                Some(path) => {
                                    match fs::write(&path, output) {
                                        Ok(_) => self.compute_info = format!("Результат записан в {}", path.display()),
                                        Err(_) => self.compute_error = "Не удалось сохранить файл с зашифрованным текстом".to_string(),
                                    };
                                },
                                None => self.compute_error = "Не удалось сохранить файл с данными".to_string()
                        };
                    },
                    //Some(KuznechickModes::MAC) => {},
                    None => {
                        self.compute_error = "Ни один из режимов работы Кузнечика не был выбран".to_string();
                    }
                };
            }
            Message::KuznechickDecryptionCompute => {
                self.info_error_msg_reset();

                if self.keys_kuznechik.keys.0.is_empty() {
                    self.compute_error = "Ключи не были созданы".to_string();
                    return Task::none();
                }

                let data = match read_file() {
                    Ok(data) => data,
                    Err(message) => {
                        self.topbar_error = message;
                        return Task::none();
                    }
                };

                match self.current_mode 
                {
                    Some(KuznechickModes::CBC) => {
                        let output = match block_cipher_modes::CipherModes::ecb_decrypt(
                            &block_cipher_modes::CipherModes{keys: self.keys_kuznechik.clone()}, 
                            &data
                        ) {
                            Ok(res) => res,
                            Err(msg) => {
                                self.compute_error = msg;
                                return Task::none();
                            }
                        };

                        let decrypted_data = match from_utf8(&output) {
                            Ok(data) => data,
                            Err(_) => {
                                self.compute_error = "Некорректные ключи для данного файла".to_string();
                                return Task::none();
                            }
                        };

                        self.kuzcnechik_text = text_editor::Content::with_text(decrypted_data);
                    },
                    Some(KuznechickModes::CFB) => {
                        let output = match block_cipher_modes::CipherModes::cfb_decrypt(
                            &block_cipher_modes::CipherModes{keys: self.keys_kuznechik.clone()}, 
                            &data,
                            self.mods_param.0 as usize,
                            self.mods_param.1 as usize,
                            &self.mods_param.2
                        ) {
                            Ok(res) => res,
                            Err(msg) => {
                                self.compute_error = msg;
                                return Task::none();
                            }
                        };

                        let decrypted_data = match from_utf8(&output) {
                            Ok(data) => data,
                            Err(_) => {
                                self.compute_error = "Некорректные ключи для данного файла".to_string();
                                return Task::none();
                            }
                        };

                        self.kuzcnechik_text = text_editor::Content::with_text(decrypted_data);
                    },
                    Some(KuznechickModes::CTR) => {
                        let mut iv:[u8; 8] = [0; 8];
                        iv.clone_from_slice(&self.mods_param.2[0..8]);

                        let output = block_cipher_modes::CipherModes::ctr_crypt(
                            &block_cipher_modes::CipherModes{keys: self.keys_kuznechik.clone()}, 
                            &data,
                            self.mods_param.0 as usize,
                            &iv
                        );

                        let decrypted_data = match from_utf8(&output) {
                            Ok(data) => data,
                            Err(_) => {
                                self.compute_error = "Некорректные ключи для данного файла".to_string();
                                return Task::none();
                            }
                        };

                        self.kuzcnechik_text = text_editor::Content::with_text(decrypted_data);
                    },
                    Some(KuznechickModes::ECB) => {
                        let output = match block_cipher_modes::CipherModes::ecb_decrypt(
                            &block_cipher_modes::CipherModes{keys: self.keys_kuznechik.clone()}, 
                            &data
                        ) {
                            Ok(res) => res,
                            Err(msg) => {
                                self.compute_error = msg;
                                return Task::none();
                            }
                        };

                        let decrypted_data = match from_utf8(&output) {
                            Ok(data) => data,
                            Err(_) => {
                                self.compute_error = "Некорректные ключи для данного файла".to_string();
                                return Task::none();
                            }
                        };

                        self.kuzcnechik_text = text_editor::Content::with_text(decrypted_data);
                    },
                    Some(KuznechickModes::OFB) => {
                        let output = block_cipher_modes::CipherModes::ofb_crypt(
                            &block_cipher_modes::CipherModes{keys: self.keys_kuznechik.clone()}, 
                            &data,
                            self.mods_param.0 as usize,
                            self.mods_param.1 as usize,
                            &self.mods_param.2
                        );

                        let decrypted_data = match from_utf8(&output) {
                            Ok(data) => data,
                            Err(_) => {
                                self.compute_error = "Некорректные ключи для данного файла".to_string();
                                return Task::none();
                            }
                        };

                        self.kuzcnechik_text = text_editor::Content::with_text(decrypted_data);
                    },
                    //Some(KuznechickModes::MAC) => {},
                    None => self.compute_error = "Ни один из режимов работы Кузнечика не был выбран".to_string()
                };
            },
            Message::InputTextEditor(content) => {
                if let Message::Streebog = self.state
                {
                    self.streebog_text.perform(content);
                }
                else if let Message::KuznechickEncryption = self.state {
                    self.kuzcnechik_text.perform(content);
                }
            },
            Message::CopyClipboard(content) =>{
                self.info_error_msg_reset();
                return clipboard::write(content).map(|_: ()| Message::CurrentState);
            },
            Message::PickFile => {
                self.info_error_msg_reset();

                match read_file() 
                {
                    Ok(bytes) =>
                    {
                        let text = match from_utf8(&bytes) {
                            Ok(text) => text,
                            Err(_) => {
                                self.topbar_error = "Некорректный файл. Используйте текстовый файл".to_string();
                                return Task::none();
                            }
                        };

                        // Определение у какого алгоритма изменять текст
                        if let Message::KuznechickEncryption = self.state
                        {
                            self.kuzcnechik_text = text_editor::Content::with_text(&text.to_string());
                        }
                        else if let Message::Streebog = self.state {
                            self.streebog_text = text_editor::Content::with_text(&text.to_string());
                        }
                    },
                    Err(message) => self.topbar_error = message
                };
            },
            _ => {}
        }

        Task::none()
    }

    pub fn view(&self) -> iced::Element<'_, Message>
    {
        let mut column:iced::widget::Column<'_, Message> = column![];

        // Отображение Top-bar
        match self.state {
            Message::Select => {
                column = column.push(column![text(format!(" User: {}", self.login)).center().size(18)]);
            },
            Message::KuznechickKeys => {
                column = column.push(
                    column![
                        row![
                            tooltip(
                                button(text('\u{E83D}')
                                    .font(CUSTOM_FONT))
                                    .style(|_theme, status| backward_button_style(status))
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
            },
            Message::KuznechickEncryption => {
                column = column.push(
                column![
                    row![
                        tooltip(
                            button(text('\u{E83D}')
                                .font(CUSTOM_FONT))
                                .style(|_theme, status| backward_button_style(status))
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
            },
            _ => {
                column = column.push(
                    column![
                        row![
                            tooltip(
                                button(text('\u{E83D}')
                                    .font(CUSTOM_FONT))
                                    .style(|_theme, status| backward_button_style(status))
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
                            text("")
                                .width(50),
                            column![
                                column![
                                    button(" RSA (Асимметричное шифрование)")
                                        .on_press(Message::RSA)
                                        .style(|_theme, status| button_style(status))
                                ].width(Length::Fill).align_x(iced::Alignment::Center),
                                text("Криптографический алгоритм с открытым ключом, основывающийся на вычислительной сложности задачи факторизации больших полупростых чисел. Криптосистема RSA стала первой системой, пригодной и для шифрования и цифровой подписи. Алгоритм используется в большом числе криптографических приложений, включая PGP, S/MIME, TLS/SSL, IPsec/IKE и других. Алгоритм шифрования с открытым и закрытым ключом приписывается Уитфилду Диффи и Мартину Хеллману, которые опубликовали эту концепцию в 1976 году. Они также ввели цифровые подписи и попытались применить теорию чисел. В их формулировке использовался секретный ключ с общим доступом, созданный путем экспоненциализации некоторого числа, простого по модулю. Однако они оставили открытой проблему реализации односторонней функции, возможно потому, что сложность факторизации в то время не была хорошо изучена. ")
                                    .width(500)
                                    .wrapping(text::Wrapping::Glyph)
                            ].height(Length::Fill),
                            column![
                                column![
                                    button(" Streebog (Хэширование)")
                                        .on_press(Message::Streebog)
                                        .style(|_theme, status| button_style(status))
                                ].width(Length::Fill).align_x(iced::Alignment::Center),
                                text("Криптографический алгоритм вычисления хеш-функции с размером блока входных данных 512 бит и размером хеш-кода 256 или 512 бит. Описывается в ГОСТ 34.11-2018 «Информационная технология. Криптографическая защита информации. Функция хэширования» — действующем межгосударственном криптографическом стандарте. Разработан Центром защиты информации и специальной связи ФСБ России с участием ОАО «ИнфоТеКС» на основе национального стандарта Российской Федерации ГОСТ Р 34.11-2012 и введен в действие с 1 июня 2019 года приказом Росстандарта № 1060-ст от 4 декабря 2018 года.")
                                    .width(500)
                                    .wrapping(text::Wrapping::Glyph)
                            ].height(Length::Fill),
                            column![
                                column![
                                    button(" Kuznehcik (Блочное шифрование)")
                                        .on_press(Message::Kuznechick)
                                        .style(|_theme, status| button_style(status))
                                ].width(Length::Fill).align_x(iced::Alignment::Center),
                                text("Симметричный алгоритм блочного шифрования с размером блока 128 бит и длиной ключа 256 бит, использующий для генерации раундовых ключей SP-сеть.Данный шифр утверждён (наряду с блочным шифром «Магма») в качестве стандарта в ГОСТ Р 34.12-2015 «Информационная технология. Криптографическая защита информации. Блочные шифры» приказом Федерального агентства по техническому регулированию и метрологии от 19 июня 2015 года № 749-ст. Стандарт вступил в действие 1 января 2016 года. Шифр разработан Центром защиты информации и специальной связи ФСБ России с участием АО «Информационные технологии и коммуникационные системы» (АО «ИнфоТеКС»). Внесён Техническим комитетом по стандартизации ТК 26 «Криптографическая защита информации».Протоколом № 54 от 29 ноября 2018 года, на основе ГОСТ Р 34.12-2015, Межгосударственным советом по метрологии, стандартизации и сертификации был принят межгосударственный стандарт ГОСТ 34.12-2018. Приказом Федерального агентства по техническому регулированию и метрологии от 4 декабря 2018 года № 1061-ст стандарт ГОСТ 34.12-2018 введён в действие в качестве национального стандарта Российской Федерации с 1 июня 2019 года.")
                                    .width(500)
                                    .wrapping(text::Wrapping::Glyph)
                            ].height(Length::Fill),
                            text("")
                                .width(50)
                        ].height(Length::Fill).spacing(100)
                    ].spacing(40));

                column = column.spacing(5);
            },
            Message::Streebog => {
                column = column.push(
                    column![
                        text("Хэширование алгоритмом Стрибог (ГОСТ Р 34.11-2018)")
                            .size(24)
                            .width(Length::Fill)
                            .align_x(iced::alignment::Horizontal::Center),
                        text("")
                            .size(48)
                            .width(Length::Fill)
                            .align_x(iced::alignment::Horizontal::Center)
                    ]
                );

                if !self.topbar_error.is_empty()
                {
                    column = column
                                .push(
                                    text("Ошибка: ".to_string() + &self.topbar_error.clone())
                                        .style(|_theme: &iced::Theme| iced::widget::text::Style {
                                            color: Some(iced::Color::from_rgb(1.0, 0.0, 0.0)), // красный цвет
                                        }));
                } else if !self.topbar_info.is_empty() {
                    column = column.push(text(self.topbar_info.clone()));
                }

                column = column.push(
                    row![
                            column![      
                                row![
                                    tooltip(
                                        button(row![
                                             text("Загрузить из "),
                                             text("\u{E812}").font(CUSTOM_FONT)
                                            ])
                                            .style(|_theme, status| button_style(status))
                                            .on_press(Message::PickFile),
                                        text("Выбор файла для хэширования"),
                                        tooltip::Position::Top
                                    ),
                                    tooltip(
                                        button(row![
                                                text("Копировать "),
                                                text("\u{F15B}").font(CUSTOM_FONT)
                                            ])
                                            .style(|_theme, status| button_style(status))
                                            .on_press(Message::CopyClipboard(self.streebog_text.text())),
                                        text(" Скопировать текст"),
                                        tooltip::Position::Top
                                    )
                                ].spacing(10),           
                                text_editor(&self.streebog_text)
                                    .on_action(Message::InputTextEditor)
                                    .placeholder("Введите или загрузите файл с исходным текстом, который необходимо захэшировать")
                                    .style(|_theme, _style| text_editor_style())
                                    .wrapping(text::Wrapping::WordOrGlyph)
                                    .height(1000)
                                    .padding(10)
                            ],
                            center(column![
                                button(column![
                                        text("Хэшировать"), 
                                        text("\u{E830}")
                                            .font(CUSTOM_FONT)
                                            .size(30)
                                            ].align_x(iced::alignment::Horizontal::Center)
                                    )
                                    .on_press(Message::StreebogCompute)
                                    .style(|_theme, status| button_style(status))
                                    .padding(30)
                            ]),
                            column![
                                row![
                                    tooltip(
                                        button(row![
                                                text("Копировать "),
                                                text("\u{F15B}").font(CUSTOM_FONT)
                                            ])
                                            .style(|_theme, status| button_style(status))
                                            .on_press(Message::CopyClipboard(self.streebog_hash.text())),
                                        text(" Скопировать Хэш"),
                                        tooltip::Position::Right
                                    )
                                ],
                                text_editor( &self.streebog_hash)
                                    .wrapping(text::Wrapping::WordOrGlyph)
                                    .placeholder("В этом поле будет отображаться результат хэширования")
                                    .style(|_theme, _style| text_editor_style())
                                    .height(1000)
                                    .padding(10) 
                            ]
                        ]
                );

                //column = column.spacing(20);
            },
            Message::Kuznechick => {
                let buttons_cont =  container(column![
                            button("Управление криптографическими ключами алгоритма Кузнечик")
                                .style(|_theme, status| button_style(status))
                                .on_press(Message::KuznechickKeys),
                            button("Шифрование алгоритмом Кузнечик")
                                .style(|_theme, status| button_style(status))
                                .on_press(Message::KuznechickEncryption)
                        ]
                    .padding(10)
                    .spacing(10)
                )
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .center_x(Length::Fill);

                return container(column![column, buttons_cont]).into();
            },
            Message::KuznechickKeys => {
                column = column.push(
                    column![
                        text("Управление криптографическими ключами алгоритма Кузнечик (ГОСТ Р 34.12-2018)")
                            .size(24)
                            .width(Length::Fill)
                            .align_x(iced::alignment::Horizontal::Center),
                        text("")
                            .size(48)
                            .width(Length::Fill)
                            .align_x(iced::alignment::Horizontal::Center)
                    ]
                );

                if !self.topbar_error.is_empty()
                {
                    column = column
                                .push(
                                    text("Ошибка: ".to_string() + &self.topbar_error.clone())
                                        .style(|_theme: &iced::Theme| iced::widget::text::Style {
                                            color: Some(iced::Color::from_rgb(1.0, 0.0, 0.0)), // красный цвет
                                        }));
                } else if !self.topbar_info.is_empty() {
                    column = column.push(text(self.topbar_info.clone()));
                }

                column = column.push(
                    row![
                            column![      
                                row![
                                    tooltip(
                                        button(row![
                                            text("Загрузить из "),
                                            text('\u{E812}')
                                                .font(CUSTOM_FONT)
                                        ])
                                            .style(|_theme, status| button_style(status))
                                            .on_press(Message::KuznechickKeysLoad),
                                        text("Выбор файла для загрузки существующих ключей"),
                                        tooltip::Position::Top
                                    ),
                                    tooltip(
                                        button(row![
                                            text("Копировать "),
                                            text('\u{F15B}')
                                                .font(CUSTOM_FONT)
                                        ])
                                            .style(|_theme, status| button_style(status))
                                            .on_press(Message::CopyClipboard(self.keys_kuznechik_text.text())),
                                        text(" Скопировать ключи в буфер обмена"),
                                        tooltip::Position::Top
                                    ),
                                    tooltip(
                                        button(row![
                                            text("Сохранить в "),
                                            text('\u{E813}')
                                                .font(CUSTOM_FONT)
                                        ])
                                            .style(|_theme, status| button_style(status))
                                            .on_press(Message::KuznechickKeysSave),
                                        text("Сохранить ключи в файл"), 
                                        tooltip::Position::Top
                                    ),
                                    button("Сгенерировать ключи")
                                        .style(|_theme, status| button_style(status))
                                        .on_press(Message::KuznechickKeysGenerate)
                                ].spacing(10),
                                text_editor(&self.keys_kuznechik_text)
                                    .placeholder("Здесь будут отображаться криптографические ключи для Кузнечика")
                                    .style(|_theme, _style| text_editor_style())
                                    .wrapping(text::Wrapping::WordOrGlyph)
                                    .height(1000)
                                    .padding(10)
                            ]]);
            },
            Message::KuznechickEncryption => {
                column = column.push(
                    column![
                        text("Шифрование алгоритмом Кузнечик (ГОСТ Р 34.12-2018)")
                            .size(24)
                            .width(Length::Fill)
                            .align_x(iced::alignment::Horizontal::Center),
                        text("")
                            .size(48)
                            .width(Length::Fill)
                            .align_x(iced::alignment::Horizontal::Center)
                    ]
                );

                if !self.topbar_error.is_empty()
                {
                    column = column
                                .push(
                                    text("Ошибка: ".to_string() + &self.topbar_error.clone())
                                        .style(|_theme: &iced::Theme| iced::widget::text::Style {
                                            color: Some(iced::Color::from_rgb(1.0, 0.0, 0.0)), // красный цвет
                                        }));
                } else if !self.topbar_info.is_empty() {
                    column = column.push(text(self.topbar_info.clone()));
                }

                column = column.push(
                    row![
                            column![      
                                row![
                                    tooltip(
                                        button(row![
                                            text("Загрузить из "),
                                            text('\u{E812}')
                                                .font(CUSTOM_FONT)
                                        ])
                                            .style(|_theme, status| button_style(status))
                                            .on_press(Message::PickFile),
                                        text("Выбор файла для шифрования"),
                                        tooltip::Position::Top
                                    ),
                                    tooltip(
                                        button(row![
                                            text("Скопировать "),
                                            text('\u{F15B}')
                                                .font(CUSTOM_FONT)
                                        ])
                                            .style(|_theme, status| button_style(status))
                                            .on_press(Message::CopyClipboard(self.kuzcnechik_text.text())),
                                        text(" Скопировать текст в буфер обмена"),
                                        tooltip::Position::Top
                                    ),
                                    tooltip(
                                        button(row![
                                            text("Сохранить в "),
                                            text('\u{E813}')
                                                .font(CUSTOM_FONT)
                                        ])
                                            .style(|_theme, status| button_style(status))
                                            .on_press(Message::KuznechickSaveFile(self.kuzcnechik_text.text())),
                                        text("Сохранить текст в файл"), 
                                        tooltip::Position::Top
                                    )
                                ].spacing(10),
                                text_editor(&self.kuzcnechik_text)
                                    .placeholder("Здесь будет отображаться текст, загруженный из файла или написанный вами, для шифрования алгоритмом Кузнечик")
                                    .style(|_theme, _style| text_editor_style())
                                    .wrapping(text::Wrapping::WordOrGlyph)
                                    .on_action(Message::InputTextEditor)
                                    .height(1000)
                                    .padding(10)
                            ],
                            center(
                                row![
                                    column![
                                        text(&self.compute_error)
                                        .style(|_theme: &iced::Theme| iced::widget::text::Style {
                                            color: Some(iced::Color::from_rgb(1.0, 0.0, 0.0)), // красный цвет
                                        }),
                                        text(&self.compute_info),
                                        combo_box(
                                            &self.kuznechik_modes, 
                                            "Выберите режим работы...", 
                                            self.current_mode.as_ref(), 
                                            Message::KuznechickChangeMode
                                        ).width(Length::Fixed(500.0)),
                                        button(text("Шифровать данные").align_x(iced::alignment::Horizontal::Center))
                                            .on_press(Message::KuznechickEncryptionCompute)
                                            .style(|_theme, status| button_style(status))
                                            .padding(15)
                                            .width(Length::Fixed(500.0)),
                                        button(text("Расшифровать данные").align_x(iced::alignment::Horizontal::Center))
                                            .on_press(Message::KuznechickDecryptionCompute)
                                            .style(|_theme, status| button_style(status))
                                            .padding(15)
                                            .width(Length::Fixed(500.0))
                                    ].spacing(15)
                                     .align_x(iced::Alignment::Center)
                                ]
                            ),
                            // column![      
                            //     row![
                            //         tooltip(
                            //             button(text('\u{E800}')
                            //                 .font(CUSTOM_FONT))
                            //                 .on_press(Message::CopyClipboard(self.kuzcnechik_cipher_text.text())),
                            //             text(" Скопировать шифротекст в буфер обмена"),
                            //             tooltip::Position::Top
                            //         ),
                            //         tooltip(
                            //             button(text('\u{E813}')
                            //                 .font(CUSTOM_FONT))
                            //                 .on_press(Message::KuznechickSaveFile(self.kuzcnechik_cipher_text.text())),
                            //             text("Сохранить шифротекст в файл"), 
                            //             tooltip::Position::Top
                            //         )
                            //     ],
                            //     text("Шифротекст"),
                            //     text_editor(&self.kuzcnechik_cipher_text)
                            //         .placeholder("Шифротекст после шифрования алгоритмом Кузнечик")
                            //         .wrapping(text::Wrapping::WordOrGlyph)
                            //         .height(1000)
                            //         .padding(10)
                            // ],
                        ]);
            },
            _ => {column = column.spacing(5);}
        }

        column.into()
    }
}

// Чтение из файла байтов
fn read_file() -> Result<Vec<u8>, String>
{
    let path = match rfd::FileDialog::new()
        .set_title(" Выберите файл...")
        .pick_file()
        {
            Some(path_buf) => path_buf,
            None => {
                return  Err("Некорректный файл".to_string());
            }
    };

    match fs::read(path)
    {
        Ok(data) => Ok(data),
        Err(_) => Err("Файла не существует".to_string())
    }
}