import jwt, { JwtPayload, SignOptions } from "jsonwebtoken"
import { string } from "zod"


export const generateToken = (payload: JwtPayload, secret: string, expiresIn:number | string) => {
    const token = jwt.sign(payload, secret, {
        expiresIn
    } as SignOptions)

 

    return token
}

export const verifyToken = (token: string, secret: string) => {

    const verifiedToken = jwt.verify(token, secret);

    return verifiedToken
}