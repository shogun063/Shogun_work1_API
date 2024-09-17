const express = require('express')
const mysql = require('mysql2')
const app = express()
const port = 4000

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const SECRET_KEY = 'UX23Y24%@&2aMb';
const crypto = require('crypto');
const cors = require('cors');

const db = mysql.createConnection(
    {
        host: "localhost",
        user: "root",
        password: "1234",
        database: "shopdee"
    }
)
db.connect()
app.use(express.json())
app.use(express.urlencoded ({extended: true}))
app.use(cors());

/*############## EMPLOYEE ##############*/
//Login (employee/admin)
app.post('/api/admin/login',
    async function(req, res){
        //Validate username
        const {username, password} = req.body;                
        let sql = "SELECT * FROM employee WHERE username=? AND isActive = 1 AND Roles = 1";        
        let employee = await query(sql, [username]);        
        
        if(employee.length <= 0){            
            return res.send( {'message':'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง','status':false} );
        }else{            
            employee = employee[0];
            empID = employee['empID'];               
            password_hash = employee['password'];       
            positionID = employee['Roles']; 
        }

        //validate a number of attempts 
        let loginAttempt = 0;
        sql = "SELECT loginAttempt FROM employee WHERE username=? AND isActive = 1 ";        
        sql += "AND lastAttemptTime >= CURRENT_TIMESTAMP - INTERVAL 24 HOUR ";        
        
        row = await query(sql, [username, username]);    
        if(row.length > 0){
            loginAttempt = row[0]['loginAttempt'];

            if(loginAttempt>= 3) {
                return res.send( {'message':'บัญชีคุณถูกล๊อก เนื่องจากมีการพยายามเข้าสู่ระบบเกินกำหนด','status':false} );    
            }    
        }else{
            //reset login attempt                
            sql = "UPDATE employee SET loginAttempt = 0, lastAttemptTime=NULL WHERE username=? AND isActive = 1";                    
            await query(sql, [username, username]);               
        }              
        

        //validate password       
        if(bcrypt.compareSync(password, password_hash)){
            //reset login attempt                
            sql = "UPDATE employee SET loginAttempt = 0, lastAttemptTime=NULL WHERE username=? AND isActive = 1";        
            await query(sql, [username, username]);   

            //get token
            const token = jwt.sign({ empID: empID, username: username, positionID: positionID }, 
                                    SECRET_KEY, { expiresIn: '1h' });                

            employee['token'] = token;
            employee['message'] = 'เข้าสู่ระบบสำเร็จ';
            employee['status'] = true;

            res.send(employee);            
        }else{
            //update login attempt
            const lastAttemptTime = new Date();
            sql = "UPDATE employee SET loginAttempt = loginAttempt + 1, lastAttemptTime=? ";
            sql += "WHERE username=? AND isActive = 1";                   
            await query(sql, [lastAttemptTime, username, username]);           
            
            if(loginAttempt >=2){
                res.send( {'message':'บัญชีคุณถูกล๊อก เนื่องจากมีการพยายามเข้าสู่ระบบเกินกำหนด','status':false} );    
            }else{
                res.send( {'message':'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง','status':false} );    
            }            
        }

    }
);

//Generate a password
function generateRandomPassword(length) {
    return crypto
        .randomBytes(length)
        .toString('base64')
        .slice(0, length)
        .replace(/\+/g, 'A')  // Replace '+' to avoid special chars if needed
        .replace(/\//g, 'B'); // Replace '/' to avoid special chars if needed
}

//Add an employee
app.post('/api/employee', 
    async function(req, res){
  
        //Receive a token
        const token = req.headers["authorization"].replace("Bearer ", "");        
    
        try{
            // Validate the token    
            let decode = jwt.verify(token, SECRET_KEY);               
            if(decode.positionID != 1) {
                return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }            

            //receive data from users
            const {username, firstName, lastName, email, gender } = req.body;

            //check existing username
            let sql="SELECT * FROM employee WHERE username=?";
            db.query(sql, [username], async function(err, results) {
                if (err) throw err;
                
                if(results.length == 0) {
                    //password and salt are encrypted by hash function (bcrypt)
                    const password = generateRandomPassword(8);
                    const salt = await bcrypt.genSalt(10); //generate salte
                    const password_hash = await bcrypt.hash(password, salt);    
                    
                    //save data into database                
                    let sql = `INSERT INTO employee(
                            username, password, firstName, lastName, email, gender, Roles
                            )VALUES(?, ?, ?, ?, ?, ?, 0)`;   
                    let params = [username, password_hash, firstName, lastName, email, gender];
                
                    db.query(sql, params, (err, result) => {
                        if (err) throw err;
                        res.send({ 'message': 'เพิ่มข้อมูลพนักงานเรียบร้อยแล้ว', 'status': true });
                    });                    

                }else{
                    res.send({'message':'ชื่อผู้ใช้ซ้ำ','status':false});
                }
            });                        
            
        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }    
    }
);

//Add an employee Admin
app.post('/api/employee/admin', 
    async function(req, res){
      
        try{

            //receive data from users
            const {username, password , firstName, lastName, email, gender } = req.body;

            //check existing username
            let sql="SELECT * FROM employee WHERE username=?";
            db.query(sql, [username], async function(err, results) {
                if (err) throw err;
                
                if(results.length == 0) {
                    const password_hash = await bcrypt.hash(password, 10);    
                    
                    //save data into database                
                    let sql = `INSERT INTO employee(
                            username, password, firstName, lastName, email, gender, Roles
                            )VALUES(?, ?, ?, ?, ?, ?, 1)`;   
                    let params = [username, password_hash, firstName, lastName, email, gender];
                
                    db.query(sql, params, (err, result) => {
                        if (err) throw err;
                        res.send({ 'message': 'เพิ่มข้อมูลพนักงานเรียบร้อยแล้ว', 'status': true });
                    });                    

                }else{
                    res.send({'message':'ชื่อผู้ใช้ซ้ำ','status':false});
                }
            });                        
            
        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }    
    }
);

function query(sql, params) {
    return new Promise((resolve, reject) => {
      db.query(sql, params, (err, results) => {
        if (err) {
          reject(err);
        } else {
          resolve(results);
        }
      });
    });
}

app.listen(port, () => {
    console.log(`HTTPS Server running on port ${port}`);
});