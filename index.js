import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";


const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 *24, 
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  if(req.isAuthenticated() ) {
    res.redirect("/index");
  } else{
    res.render("home.ejs");
  }
});

app.get("/index", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const userIdResult = await db.query("SELECT id FROM users WHERE email = $1", [req.user.email]);
      const userId = userIdResult.rows[0].id;
      const result = await db.query("SELECT * FROM books WHERE user_id = $1", [userId]);
      const books = result.rows;
      res.render("index.ejs", { listBooks: books });
    } catch (err) {
      console.error("Error retrieving books:", err);
      res.status(500).send("Internal Server Error");
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/add", (req, res) => {
  res.render("new-entries.ejs");
});

app.get("/my-notes", (req, res) => {
  res.render("notes.ejs",);
});

app.get("/login", async (req, res) => {
  res.render("login.ejs")
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/index",
    failureRedirect: "/login",
  })
);

app.get("/my-notes/:id", async (req, res) => {
  const id = req.params.id;
  
  try {
    const result = await db.query("SELECT * FROM books WHERE id = $1", [id]);
    const book = result.rows[0];
    
    if (book) {
      res.render("notes.ejs", { book });
    } else {
      res.send("No notes available for this book.");
    }
  } catch (err) {
    console.log(err);
    res.redirect("/index");
  }
});

app.post("/add-books", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const userIdResult = await db.query("SELECT id FROM users WHERE email = $1", [req.user.email]);
      const userId = userIdResult.rows[0].id;
      const { title, author, rating, summary, isbn, notes, date } = req.body;
      await db.query("INSERT INTO books (title, author, rating, summary, isbn_number, notes, date_read, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)", [title, author, rating, summary, isbn, notes, date, userId]);
      res.redirect("/index");
    } catch (err) {
      console.error("Error adding book:", err);
      res.redirect("/add");
    }
  } else {
    res.redirect("/login");
  }
});

app.post("/edit", async (req,res) => {
  const id = req.body.editBookId

  try {
    const result = await db.query('SELECT * FROM books WHERE id = $1', [id]);
    const book = result.rows[0];
    res.render("edit", {book});
  } catch (err) {
    console.log(err);
  }
  
});

app.post("/update", async (req, res) => {
  if (req.isAuthenticated() ) {
    const { title, author, isbn, rating, summary, date, id, notes } = req.body;

  try {
    await db.query("UPDATE books SET title = $1, author = $2, rating = $3, summary = $4, isbn_number = $5, date_read = $6, notes = $7 WHERE id = $8",
      [title, author, rating, summary, isbn, date, notes, id]);
     res.redirect("/index"); 
  } catch (err) {
    console.error("Error updating book:", err);
  }
  } else {
    res.redirect("/login");
  }
  
});

app.post("/delete", async (req, res) => {
  const id = req.body.deleteBookId;
  try {
    await db.query("DELETE FROM books WHERE id = $1", [id]);
    res.redirect("/index");
  } catch (err) {
    console.log(err);
    res.redirect("/index");
  }
});


app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/index",
    failureRedirect: "/login",
  })
);


app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const existingUser = await db.query("SELECT * FROM users WHERE email = $1", [username]);
    if (existingUser.rows.length > 0) {
      res.send("User already exists");
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id", [username, hashedPassword]);
    const userId = result.rows[0].id;
    req.session.userId = userId;
    res.redirect("/index");
  } catch (err) {
    console.error(err);
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
