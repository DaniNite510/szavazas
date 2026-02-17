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
// ---- végpontok ----

app.post('/regisztracio', async (req, res) => {
    const { email, felhasznalonev, jelszo, admin } = req.body;
    if (!email || !felhaznalonev || !jelszo || !admin) {
        return res.status(400).json("hiányzó bemeneti adatok")
    }
    try {
        const isValid = await emailValidator(email)
        if (!isValid) {
            return res.status(401).json({ message: "nem létező email" })
        }
        const emailFelhasznalonevSQL = 'SELECT * FROM `felhasznalok` WHERE `email` = ? OR felhasznalonev = ?';
        const [exists] = await db.query('', [email, felhasznalonev])
        if (exists.length) {
            return res.status(402).json({ message: "az email cím vagy a felhasználónév foglalt" })
        }
        const hash = await bcrypt.hash(jelszo, 10);
        const regiszracioSQL = 'INSERT INTO felhasznalok (email, felhasznanev, jelszo, admin) VALUES(?,?,?,?)'
        const [result] = await db.query(regiszracioSQL, [email, felhasznalonev, hash, admin])

        return res.status(200).json({
            message: "Sikeres regisztráció",
            id: result.insertId
        })
    }
    catch (error) {
        console.error.log(error)
        return res.stzatus(500).json({ message: "Szerverhiba" })
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
                return res.status(400).json({ message: "Ezzel a felhasznaonevvel címmel még nem regisztráltak" })
            }
        }


        const ok = bcrypt.compare(jelszo, hashJelszo)
        if(!ok) {
            return res.status(403).json({message:"Rossz jelszót adtál meg"})
        }
        if (ok) {
            const token = jwt.sign(
                {id: user.id, email: user.email, felhasznalonev:user.felhasznalonev, admin: user.admin},
                JWT_SECRET,
                {expiresIn: JWT_EXPIRES_IN}
            )
        }
        res.cookie(COOKIE_NAME, token, COOKIE_OPTS)
        res.status(200).json({message: "Sikeres belépés"})
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "szerverhiba" })
    }
})

app.get('/adataim',auth, async (req, res) => {

})





// ---- szerver elindítása

app.listen(PORT, HOST, () => {
    console.log(`API fut: http://${HOST}:${PORT}/`)
})