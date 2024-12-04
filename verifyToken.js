import jsonwebtoken from "jsonwebtoken";

const verifyTokenMiddleware = (req, res, next) => { 
    const { token } = req.body; 
    const secretKey="h8u5896utri3i90a(%(Tfi*(%)))";
    if (!token) return res.status(403).json({  
        msg: "No token present" 
    }); 
    try { 
        const decoded = jsonwebtoken.verify(token,  
            secretKey); 
        req.user = decoded; 
    } catch (err) { 
        return res.status(401).json({  
            msg: "Invalid Token" 
        }); 
    } 
    next(); 
}; 

export default verifyTokenMiddleware;