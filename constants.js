module.exports = {
    USER_EXISTS: "User already exists",
    USER_NOT_EXISTS: "Cannot find user",
    NOT_ALLOWED: "Not allowed",
    LOGGED_OUT: "Successfully logged out",
    BAD_USER: "The user does not exist or isn't logged in",

    // HTTP status codes

    HTTP_STATUS_OK: 200,
    HTTP_STATUS_CREATED: 201,
    HTTP_STATUS_UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    HTTP_STATUS_BAD_REQUEST: 400,
    INTERNAL_SERVER_ERROR: 500,

    // salt rounds 
    SALT_ROUNDS: 10,

    // sql statements
    EXIST_LOGIN_SQL: `SELECT * FROM allUsers WHERE login=?`,
    INSERT_SQL: `INSERT INTO allUsers (firstname, lastname, login, hashedPassword) VALUES (?,?,?,?)`,
    UPDATE_REFRESH_SQL: `UPDATE allUsers SET refreshtoken=? WHERE login=?`,
    SELECT_REFRESH_SQL: `SELECT refreshtoken FROM allUsers WHERE refreshtoken=?`,
    LOGOUT_USER: `UPDATE allUsers SET refreshtoken=\"null\" WHERE login=?`,
    GET_ALL_QUOTES: `SELECT * FROM quote`,

    //routes
    REGISTER: '/register',
    LOGIN: '/login',
    REFRESHTOKEN: '/refreshtoken',
    LOGOUT: '/logout',
    QUOTES: '/quotes',

    EXPIRES_IN: '15m'
};
