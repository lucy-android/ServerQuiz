module.exports = {
    USER_EXISTS: "User already exists",
    USER_NOT_EXISTS: "Cannot find user",
    NOT_ALLOWED: "Not allowed",
    LOGGED_OUT: "Successfully logged out",
    BAD_USER: "The user does not exist or isn't logged in",

    // HTTP status codes

    HTTP_STATUS_OK: 200,
    HTTP_STATUS_CREATED : 201,
    HTTP_STATUS_UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    HTTP_STATUS_BAD_REQUEST: 400,
    INTERNAL_SERVER_ERROR: 500,

    // salt rounds 
    SALT_ROUNDS : 10,

    // sql statements
    EXIST_LOGIN_SQL : `SELECT * FROM allUsers WHERE login=?`,
    INSERT_SQL : `INSERT INTO allUsers (firstname, lastname, login, hashedPassword) VALUES (?,?,?,?)`,

};
