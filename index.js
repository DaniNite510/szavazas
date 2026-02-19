const express = require('express')
const cors = require('cors')
const cookieParser = require('cookie-parser')
const mysql = require('mysql2/promise')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const emailValidator = require('node-email-verifier')

//---- config ----
const PORT = 3000;
const HOST = 'localhost'
const JWT_SECRET = 'nagyon_nagyon_titkos_egyedi_jelszo'
const JWT_EXPIRES_IN = '7d'
const COOKIE_NAME = 'auth-token'

// ---- cookie beállítás ----

const COOKIE_OPTS = {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,
}

// ---- adatbázis beállítás ----
const db = mysql.createPool({
    host: 'localhost',
    port: '3306',
    database: 'szavazas',
    user: 'root',
    password: ''
})

// ---- App ----

const app = express();

app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin: '*',
    credentials: true
}))
// ---- Middleware ----

function auth(req,res, next){
    const token = req.cookies[COOKIE_NAME];
    if(!token){
        return res.status(409).json({message:"Nem vagy bejelentkezve"})
    }
    try {
        req.user = jwt.verify(token, JWT_SECRET)
        next();
    } catch (error) {
        return res.status(410).json({message: "Nem érvényes token"})
    }}
// ---- végpontok ----

app.post('/regisztracio', async (req, res) => {
    const { email, felhasznalonev, jelszo, admin } = req.body;
    if (!email || !felhasznalonev || !jelszo || !admin) {
        return res.status(400).json("hiányzó bemeneti adatok")
    }
    try {
        const isValid = await emailValidator(email)
        if (!isValid) {
            return res.status(401).json({ message: "nem létező email" })
        }
        const emailFelhasznalonevSQL = 'SELECT * FROM `felhasznalok` WHERE `email` = ? OR felhasznalonev = ?';
        const [exists] = await db.query(emailFelhasznalonevSQL, [email, felhasznalonev])
        if (exists.length) {
            return res.status(402).json({ message: "az email cím vagy a felhasználónév foglalt" })
        }
        const hash = await bcrypt.hash(jelszo, 10);
        const regiszracioSQL = 'INSERT INTO felhasznalok (email, felhasznalonev, jelszo, admin) VALUES(?,?,?,?)'
        const [result] = await db.query(regiszracioSQL, [email, felhasznalonev, hash, admin])

        return res.status(200).json({
            message: "Sikeres regisztráció",
            id: result.insertId
        })
    }
    catch (error) {
        console.log(error)
        return res.status(500).json({ message: "Szerverhiba" })
    }
})

app.post('/belepes', async (req, res) => {
    const { felhasznalonevvagyEmail, jelszo } = req.body;
    if (!felhasznalonevvagyEmail || !jelszo) {
        return res.json({ message: "hiányos belépési adatok" })
    }
    try {
        const isValid = await emailValidator(felhasznalonevvagyEmail)
        let hashJelszo = "";
        let user = {}
        if (isValid) {
            const sql = 'SELECT * FROM felhasznalok WHERE email = ?'
            const [rows] = await db.query(sql, [felhasznalonevvagyEmail])
            if (rows.length) {
                 user = rows[0];
                hashJelszo = user.jelszo;
            }
            else {
                return res.status(400).json({ message: "Ezzel az email címmel még nem regisztráltak" })
            }
        }
        else {
            const sql = 'SELECT * FROM felhasznalok WHERE felhasznalonev = ?'
            const [rows] = await db.query(sql, [felhasznalonevvagyEmail])
            if (rows.length) {
                 user = rows[0];
                hashJelszo = user.jelszo;
            }
            else {
                return res.status(400).json({ message: "Ezzel a felhasznaonevvel vagy email címmel még nem regisztráltak" })
            }
        }


        const ok = bcrypt.compare(jelszo, hashJelszo)
        if(!ok) {
            return res.status(403).json({message:"Rossz jelszót adtál meg"})
        }
        const token = jwt.sign(
            {id: user.id, email: user.email, felhasznalonev:user.felhasznalonev, admin: user.admin},
            JWT_SECRET,
            {expiresIn: JWT_EXPIRES_IN}
        )
        res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
        res.status(200).json({message: "Sikeres belépés"})
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "szerverhiba" })
    }
})
//VÉDETT
app.post('/kijelentkezes', async (req,res)=>{
res.clearCookie(COOKIE_NAME, {path: '/'});
res.status(200).json({message: "Sikeres kijelentkezés"})
})
//VÉDETT
app.get('/adataim',auth, async (req, res) => {
    res.status(200).json(req.user)
})

app.put('/email', auth, async (req,res) => {
    const {ujEmail} = req.body;
    if (!ujEmail) {
        return res.status(401).json({message:"Az új email megadása kötelező"})
    }
    const isValid = await emailValidator(ujEmail)
    if(!isValid) {
        return res.status(402).json({message: "Az email formátuma nem megfelelő"})
    }
    try {
        const sql = 'UPDATE felhasznalok SET email = ? Where id=?'
        const [update] = await db.query(sql,[ujEmail]);
        if (!update.insertId) {
            return res.status(403).json({message:"Az email-cím már foglalt"})
        } 
        const sql2 = 'Update felhasznalok set email = ? where id = ? '
        await db.query (sql2, [ujEmail, req.user.id]);
        return res.status(200).json({message: "Sikeres email-cím változtatás"})
    } catch (error) {
        console.log(error)
        res.status(500).json({message:"Szerverhiba"})
    }
})

app.put('/felhasznalonev', auth, async (req,res) => {
    const {ujFelhasznalonev} = req.body;
    if (!ujFelhasznalonev) {
        return res.status(401).json({message:"Az új felhasználónév megadása kötelező"})
    }
    try {
        const sql = 'UPDATE felhasznalok SET felhasznalonev = ? Where id=?'
        const [update] = await db.query(sql,[ujFelhasznalonev]);
        if (!update.insertId) {
            return res.status(403).json({message:"A felhasználónév már foglalt"})
        } 
        const sql2 = 'Update felhasznalok set email = ? where id = ? '
        await db.query (sql2, [ujFelhasznalonev, req.user.id]);
        return res.status(200).json({message: "Sikeres felhasználónév változtatás"})
    } catch (error) {
        console.log(error)
        res.status(500).json({message:"Szerverhiba"})
    }
})

app.put('/jelszo', async(req,res)=>{
    const {jelenlegiJelszo, ujJelszo}= req.body
    if (!jelenlegiJelszo || !ujJelszo)
    {
        return res.status(400).json({message: "Hiányzó bemeneti adatok"})
    }
    try {
        
            const sql = 'SELECT * FROM felhasznalok WHERE id = ?'
            const [rows] = await db.query(sql, [req.user.id])
            const user = rows[0];
            const hashJelszo = user.jelszo
            const ok = bcrypt.compare(jelenlegiJelszo, hashJelszo)
            if(!ok) {
                return res.status(401).json({message: ""})
            }
            const hashUjJelszo = await bcrypt.hash(ujJelszo, 10)

            const sql2 = "UPDATE felhasznalok SET jelszo = ? Where id = ?"
            await db.query(sql2, [hashJelszo, req.user.id]);
            return res.status(200).json({message: "Sikeresen módosult a jelszavad"})
    }
    catch (error) {
        console.log(error)
        res.status(500).json({message: "Szerverhiba"})
    }
})

app.delete('./fiokom', auth,async (req, res))
{
    try {
        const sql = 'DELETE FROM felhszanalok where id = ?'
        await db.query(sql, [req.user.id])
        res.clearCookie(COOKIE_NAME, {path : '/'})
    res.status(200).json({message: "Sikeres fióktörlés"})
    } catch (error) {
        console.log(error)
        res.status(500).json({message: "Szerverhiba"})
    }
}



// ---- szerver elindítása

app.listen(PORT, HOST, () => {
    console.log(`API fut: http://${HOST}:${PORT}/`)
})