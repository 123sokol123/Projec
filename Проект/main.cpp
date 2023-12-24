#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sqlite3.h>
#include <thread>

struct UserData {
    int64_t id;
    std::string name;
};

struct User {
    std::string name;
    int64_t userID;
    std::string accessToken;
    std::vector<int> access;
};

struct Authenticate {
    bool is_done;
    std::string code;
} authenticate;

const std::string CLIENT_ID = "4b5bec0082e38328530d";
const std::string CLIENT_SECRET = "5fd63e5ebd73e67bb4c0da10c4a4d918d3f3e18c";

std::map<int64_t, User> users;

void startServer();
void handleOauth(const httplib::Request& req, httplib::Response& res);
std::string getAccessToken(const std::string& code);
UserData getUserData(const std::string& accessToken);

class AuthModule {
public:
    AuthModule(const std::string& dbPath);
    ~AuthModule();

    bool Initialize();
    bool RegisterUser(const std::string& username, const std::string& password, const std::string& githubId, const std::string& telegramId, const std::vector<std::string>& roles, const std::string& fullName, const std::string& groupNumber);
    bool DeleteUser(const std::string& username);
    bool ChangeUserRoles(const std::string& username, const std::vector<std::string>& newRoles);
    bool ChangeUserData(const std::string& username, const std::string& newFullName, const std::string& newGroupNumber);
    bool UserExists(const std::string& idType, const std::string& idValue);
    bool GetUserInformation(const std::string& idType, const std::string& idValue, std::string& userInformation);
    bool GetUserRoles(const std::string& idType, const std::string& idValue, std::vector<std::string>& userRoles);
    std::vector<std::string> GetUserRoles(const std::string& idType, const std::string& idValue);

private:
    sqlite3* db;
    std::string databasePath;

    bool ExecuteSQL(const std::string& sql);
};

AuthModule::AuthModule(const std::string& dbPath) : db(nullptr), databasePath(dbPath) {
}

AuthModule::~AuthModule() {
    if (db) {
        sqlite3_close(db);
    }
}

bool AuthModule::Initialize() {
    int result = sqlite3_open(databasePath.c_str(), &db);
    if (result != SQLITE_OK) {
        std::cerr << "Failed to open the database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    std::string createTableSQL = "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY,"
        "password TEXT,"
        "github_id TEXT,"
        "telegram_id TEXT,"
        "roles TEXT,"
        "full_name TEXT,"
        "group_number TEXT);";
    if (!ExecuteSQL(createTableSQL)) {
        return false;
    }

    return true;
}

bool AuthModule::RegisterUser(const std::string& username, const std::string& password, const std::string& githubId, const std::string& telegramId, const std::vector<std::string>& roles, const std::string& fullName, const std::string& groupNumber) {
    std::string insertUserSQL = "INSERT INTO users (username, password, github_id, telegram_id, roles, full_name, group_number) VALUES (?, ?, ?, ?, ?, ?, ?);";

    if (ExecuteSQL(insertUserSQL)) {
        sqlite3_stmt* stmt;
        int result = sqlite3_prepare_v2(db, insertUserSQL.c_str(), -1, &stmt, nullptr);

        if (result == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, githubId.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 4, telegramId.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 5, join(roles, ",").c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 6, fullName.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 7, groupNumber.c_str(), -1, SQLITE_STATIC);

            result = sqlite3_step(stmt);
            sqlite3_finalize(stmt);

            if (result == SQLITE_DONE) {
                return true;
            }
        }
    }

    return false;
}

bool AuthModule::DeleteUser(const std::string& username) {
    std::string deleteUserSQL = "DELETE FROM users WHERE username = ?;";

    if (ExecuteSQL(deleteUserSQL)) {
        sqlite3_stmt* stmt;
        int result = sqlite3_prepare_v2(db, deleteUserSQL.c_str(), -1, &stmt, nullptr);

        if (result == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
            result = sqlite3_step(stmt);
            sqlite3_finalize(stmt);

            if (result == SQLITE_DONE) {
                return true;
            }
        }
    }

    return false;
}

bool AuthModule::ChangeUserRoles(const std::string& username, const std::vector<std::string>& newRoles) {
    std::string updateUserRolesSQL = "UPDATE users SET roles = ? WHERE username = ?;";

    if (ExecuteSQL(updateUserRolesSQL)) {
        sqlite3_stmt* stmt;
        int result = sqlite3_prepare_v2(db, updateUserRolesSQL.c_str(), -1, &stmt, nullptr);

        if (result == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, join(newRoles, ",").c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);

            result = sqlite3_step(stmt);
            sqlite3_finalize(stmt);

            if (result == SQLITE_DONE) {
                return true;
            }
        }
    }

    return false;
}

bool AuthModule::ChangeUserData(const std::string& username, const std::string& newFullName, const std::string& newGroupNumber) {
    std::string updateUserDataSQL = "UPDATE users SET full_name = ?, group_number = ? WHERE username = ?;";

    if (ExecuteSQL(updateUserDataSQL)) {
        sqlite3_stmt* stmt;
        int result = sqlite3_prepare_v2(db, updateUserDataSQL.c_str(), -1, &stmt, nullptr);

        if (result == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, newFullName.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, newGroupNumber.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, username.c_str(), -1, SQLITE_STATIC);

            result = sqlite3_step(stmt);
            sqlite3_finalize(stmt);

            if (result == SQLITE_DONE) {
                return true;
            }
        }
    }

    return false;
}

bool AuthModule::UserExists(const std::string& idType, const std::string& idValue) {
    std::string query = "SELECT username FROM users WHERE " + idType + " = ?;";
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);

    if (result == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, idValue.c_str(), -1, SQLITE_STATIC);

        result = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (result == SQLITE_ROW) {
            return true;
        }
    }

    return false;
}

std::vector<std::string> AuthModule::GetUserRoles(const std::string& idType, const std::string& idValue) {
    std::vector<std::string> userRoles;

    std::string query = "SELECT roles FROM users WHERE " + idType + " = ?;";
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);

    if (result == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, idValue.c_str(), -1, SQLITE_STATIC);

        result = sqlite3_step(stmt);
        if (result == SQLITE_ROW) {
            const char* rolesString = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            userRoles = split(rolesString, ','); // Разделение строки с ролями на вектор
        }

        sqlite3_finalize(stmt);
    }

    return userRoles;
}

bool AuthModule::ExecuteSQL(const std::string& sql) {
    char* errMsg = nullptr;
    int result = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);

    if (result != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }

    return true;
}
bool AuthModule::GetUserInformation(const std::string& idType, const std::string& idValue, std::string& userInformation) {
    std::string query = "SELECT * FROM users WHERE " + idType + " = ?;";
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);

    if (result == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, idValue.c_str(), -1, SQLITE_STATIC);

        result = sqlite3_step(stmt);
        if (result == SQLITE_ROW) {
            // Формируем строку с информацией о пользователе
            std::ostringstream oss;
            oss << "ID: " << sqlite3_column_text(stmt, 0) << "\n";
            oss << "Username: " << sqlite3_column_text(stmt, 1) << "\n";
            oss << "Password: " << sqlite3_column_text(stmt, 2) << "\n";
            // Добавьте остальные поля, если необходимо

            userInformation = oss.str();
            sqlite3_finalize(stmt);
            return true;
        }
    }

    return false;
}

bool AuthModule::GetUserRoles(const std::string& idType, const std::string& idValue, std::vector<std::string>& userRoles) {
    std::string query = "SELECT roles FROM users WHERE " + idType + " = ?;";
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);

    if (result == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, idValue.c_str(), -1, SQLITE_STATIC);

        result = sqlite3_step(stmt);
        if (result == SQLITE_ROW) {
            const char* rolesString = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            userRoles = split(rolesString, ','); // Разделение строки с ролями на вектор
            sqlite3_finalize(stmt);
            return true;
        }
    }

    return false;
}
std::string generateAuthLink(const std::string& chatId) {
    // URL, по которому проходит аутентификация
    std::string authUrl = "https://github.com/login/oauth/authorize";

    // Ваш клиентский идентификатор GitHub
    std::string clientId = "Ваш_Клиентский_ID";

    // Перенаправление после успешной аутентификации
    std::string redirectUri = "http://ваш_сервер/redirect_uri";

    // Значения областей, к которым запрашивается доступ
    std::string scope = "user";

    // Составляем URL для аутентификации
    std::string authLink = authUrl + "?client_id=" + clientId +
        "&redirect_uri=" + redirectUri +
        "&scope=" + scope +
        "&state=" + chatId;  // Используем chatId как состояние

    return authLink;
}

int main() {
    std::thread startServer;

    std::string authURL = "https://github.com/login/oauth/authorize?client_id=" + CLIENT_ID;
    while (!authenticate.is_done) {
        std::cout << "Чтобы зайти, перейдите по ссылке:\n" << authURL << std::endl;
        std::cout << "и нажмите Enter" << std::endl;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    std::string accessToken = getAccessToken(authenticate.code);
    UserData userData = getUserData(accessToken);

    auto userIt = users.find(userData.id);
    if (userIt == users.end()) {
        // Добавляем пользователя с дефолтными правами
        users[userData.id] = { userData.name, userData.id, accessToken, {13} };
    }
    User& user = users[userData.id];
    std::cout << "Добро пожаловать, " << user.name << std::endl;

    // Авторизация
    std::cout << "В какую зону хотите попасть? ";
    int area;
    std::cin >> area;

    AuthModule authModule("auth_database.db");
    if (authModule.Initialize()) {
        // Ваши методы проверки доступа и логика работы с AuthModule здесь...

        if (std::find(user.access.begin(), user.access.end(), area) == user.access.end()) {
            std::cout << "Нет доступа в эту зону" << std::endl;
            return 0;
        }
        std::cout << "Доступ получен" << std::endl;
    }

    return 0;
}

void startServer() {
    httplib::Server server;
    server.Post("/oauth", handleOauth);

    server.Get("/authlink", [](const httplib::Request& req, httplib::Response& res) {   
        // Получаем chat_id из параметров запроса, например, req.get_param_value("chat_id")
        std::string chatId = req.get_param_value("chat_id");

        // Генерируем ссылку для аутентификации
        std::string authLink = generateAuthLink(chatId);

        // Отправляем ссылку в модуль Бота (здесь нужно использовать ваш механизм взаимодействия)
        // Например, отправка HTTP-запроса к модулю Бота
        sendAuthLinkToBot(chatId, authLink);

        // Отправляем ответ клиенту (ваша реализация может отличаться)
        res.set_content("Auth link sent", "text/plain");
        });

    server.listen("localhost", 8080);
}


void handleOauth(const httplib::Request& req, httplib::Response& res) {
    std::string responseHtml = "<html><body><h1>Вы НЕ аутентифицированы!</h1></body></html>";

    std::string code = req.get_param_value("code");
    if (!code.empty()) {
        authenticate.is_done = true;
        authenticate.code = code;
        responseHtml = "<html><body><h1>Вы аутентифицированы!</h1></body></html>";
    }

    res.set_content(responseHtml, "text/html");
}

std::string getAccessToken(const std::string& code) {
    httplib::Client client("https://github.com");
    httplib::Params params{
        {"client_id", CLIENT_ID},
        {"client_secret", CLIENT_SECRET},
        {"code", code}
    };

    auto response = client.Post("/login/oauth/access_token", params);
    if (response && response->status == 200) {
        nlohmann::json responseJson = nlohmann::json::parse(response->body);
        return responseJson["access_token"];
    }

    return "";
}

UserData getUserData(const std::string& accessToken) {
    httplib::Client client("https://api.github.com");
    auto response = client.Get("/user", { {"Authorization", "Bearer " + accessToken} });
    if (response && response->status == 200) {
        UserData userData;
        nlohmann::json responseJson = nlohmann::json::parse(response->body);
        userData.id = responseJson["id"];
        userData.name = responseJson["name"];
        return userData;
    }

    return UserData{ -1, "" };
}

std::string join(const std::vector<std::string>& elements, const std::string& separator) {
    std::string result;
    for (size_t i = 0; i < elements.size(); ++i) {
        if (i > 0) result += separator;
        result += elements[i];
    }
    return result;
}

std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(s);
    std::string token;
    while (getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}
