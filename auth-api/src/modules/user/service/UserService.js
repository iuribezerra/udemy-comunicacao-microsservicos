import bcrypt from "bcrypt"
import jwt from "jsonwebtoken";
import UserRepository from "../repository/UserRepository.js";
import UserException from "../exception/UserException.js";
import * as httpStatus from "../../../config/constants/httpStatus.js"
import * as secrets from "../../../config/constants/apiSecret.js"
class UserService {

    async findByEmail(req) {
        try {
            const { email } = req.params;
            const { authUser } = req;
            this.validateRequestData(email);
            let user = await UserRepository.findByEmail(email);
            this.validateUserNotFound(user);
            this.validateAuthenticatedUser(user, authUser);
            return {
                status: httpStatus.SUCCESS,
                user: {
                    id: user.id,
                    nome: user.nome,
                    email: user.email,
                }
            }
        } catch (error) {
            return {
                status: error.status ? error.status : httpStatus.INTERNAL_SERVER_ERROR,
                message: error.message
            }
        }
    }

    validateRequestData(email) {
        if (!email) {
            throw new UserException(httpStatus.BAD_REQUEST, "User email was not informed.");
        }
    }

    validateUserNotFound(user) {
        if (!user) {
            throw new UserException(httpStatus.BAD_REQUEST, "User was not found");
        }
    }

    async getAccessToken(req) {
        try {
            const { email, password } = req.body;
            this.validateAccessTokenData(email, password);
            let user = await UserRepository.findByEmail(email);
            this.validateUserNotFound(user);
            await this.validadePassword(password, user.password);
            const authUser = { id: user.id, name: user.name, email: user.email };
            const accessToken = jwt.sign({ authUser }, secrets.API_SECRET, { expiresIn: "1d" });

            return {
                status: httpStatus.SUCCESS,
                accessToken
            }
        } catch (error) {
            return {
                status: error.status ? error.status : httpStatus.INTERNAL_SERVER_ERROR,
                message: error.message
            }
        }
    }

    validateAccessTokenData(email, password) {
        if (!email || !password) {
            throw new UserException(httpStatus.UNAUTHORIZES, "Email and password must be informed.");
        }
    }

    async validadePassword(password, hashPassword) {
        if (!await bcrypt.compare(password, hashPassword)) {
            throw new UserException(httpStatus.UNAUTHORIZES, "Password doesn't match");
        }
    }

    validateAuthenticatedUser(user, authUser) {
        if (!authUser || user.id !== authUser.id) {
            throw new UserException(httpStatus.FORBIDDEN, "You cannot see this user data")
        }
    }
}

export default new UserService();