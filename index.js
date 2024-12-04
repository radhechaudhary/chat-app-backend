import express from "express";
import cors from "cors"
import bodyParser from "body-parser";
import jsonwebtoken from "jsonwebtoken";
import pg from 'pg'
import verifyTokenMiddleware from "./verifyToken.js";
import { createServer } from "http";
import { Server } from "socket.io";
import bcrypt from 'bcryptjs';
import users from "./user_socket.js";
import users_online from "./users_online.js";

const PORT=4000;
const app=express();
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true })); //body parser to encode body data from frontend
app.use(bodyParser.json());
const server = createServer(app);
const io = new Server(server, {
    cors: {
      origin: "http://localhost:3000", // Allow requests from this origin
      methods: ["GET", "POST"],       // Allow these HTTP methods
    },
  });
  

const db=new pg.Client({
    user:"postgres",
    database:"chat-app",
    port:5432,
    host:"localhost",
    password:"Radhe@1101"
})
db.connect();

app.get("/", (req,res)=>{
    res.send("hello")
})

io.on('connection',(socket)=>{  // socket connection
    socket.on('register', (userId) => { // regetser socketId
        users[userId] = socket.id;
      });

      socket.on('newChat',async(searchingValue)=>{  // search for the username
        const data=await db.query('select username, name from users where username=$1',[searchingValue]);
        if(data.rows.length>0){
            io.to(socket.id).emit('AddnewChat', data.rows[0])
        }
        else{
            io.to(socket.id).emit('AddnewChat',{}) 
        }
      })

      socket.on('update_status', (username, update)=>{ // update online users list
        users_online[username]=update;
        socket.emit('update_status_list', users_online);  // send list to every users
      })
      socket.on('privateMessage', ({recieverUsername, senderUsername, message})=>{  // sending messages
        io.to(users[recieverUsername]).emit('privateMessage',  { username:senderUsername,  message: message}); 
      }) 
      socket.on('unregester', (userId)=>{ //  unregester
        delete users[userId];
      })
})

app.post('/login', async(req, res)=>{  //login route
    const username=req.body.username;
    const password=req.body.password;
    try{
        const data=await db.query("select password, sr_no from users where username=$1",[username]);
        const isMatch = await bcrypt.compare(password, data.rows[0].password);
        if(isMatch){
            const secretKey="h8u5896utri3i90a(%(Tfi*(%)))";
            const payload={
                userId:data.rows[0].sr_no,
                username:username
            }
            const token = jsonwebtoken.sign(payload, secretKey);
            const a=await db.query("update users set token=$1 where username=$2",[ token, username ])
            res.json({status:"valid", username:username, token:token});
        }
        else{
            res.send("password not valid")
        }
    }
    catch(err){
        console.log(err)
        res.send("username not found")
    }
    
})
app.post('/signup', async(req, res)=>{   // signUp route
    const name=req.body.name;
    const username=req.body.username;
    const password=req.body.password;
    if((password.length<8) || (!password.includes("_") && !password.includes("@") && !password.includes("#") && !password.includes("&") && !password.includes("-") && !password.includes("%") && !password.includes("$") && !password.includes("*"))){
        res.send("password must have 8 characters and must include symbols like @#$%*&")
      }
      else{
    try{
        const saltRounds = 10; // Higher rounds = more security but slower
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const data=await db.query("insert into users (name, username, password) values($1,$2,$3) returning sr_no",[name, username, hashedPassword]);
        const secretKey="h8u5896utri3i90a(%(Tfi*(%)))";
        const payload={
            userId:data.rows[0].sr_no,
            username:username
        }
        const token = jsonwebtoken.sign(payload, secretKey);
        const a=await db.query("update users set token=$1  where username=$2",[ token,  username ])
        res.json({status:"valid", username:username, token:token});
        }
    catch(err){
        console.log(err)
        res.send("username already present")
    }}
})

app.post('/authenticate-user',verifyTokenMiddleware, async(req, res)=>{
   const {username, token}=req.body;
   try{
    const data=await db.query("select token from users where username=$1",[username])
        if(data.rows[0].token===token){
            res.send("valid")
        }
        else{
            res.send("error")
        }
    }
    catch(err){
        console.log(err)
    }
   
})

server.listen(PORT,()=>{
    console.log(`connected on port ${PORT}`);
})