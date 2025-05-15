import jsonwebtoken from "jsonwebtoken";
import dotenv from 'dotenv'

dotenv.config();

const verifyTokenMiddleware = (req, res, next) => { 
    const token = req.headers.authorization?.split(' ')[1];
    const secretKey=process.env.SECRET_KEY;
    if (!token) return res.status(403).json({  
        msg: "No token present" 
    }); 
    try { 
        const decoded = jsonwebtoken.verify(token, secretKey); 
        req.user = decoded; 
    } catch (err) { 
        return res.status(401).json({  
            msg: "Invalid Token" 
        }); 
    } 
    next(); 
}; 

export default verifyTokenMiddleware;