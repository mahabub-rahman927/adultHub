/**
 * Video Hub Pro — Backend Server
 * Stack: Node.js · Express · MongoDB (Mongoose) · bcrypt · express-session
 *
 * Install:
 *   npm install express mongoose bcryptjs express-session connect-mongo cors node-fetch
 *
 * Run:
 *   node server.js
 *
 * Environment variables (create a .env file or set them in your shell):
 *   MONGO_URI      = mongodb://localhost:27017/videohub   (default shown)
 *   SESSION_SECRET = your-super-secret-string
 *   PORT           = 3000
 *   VIDEO_API_BASE = https://your-video-source-api.com   (your existing video API)
 */

require("dotenv").config();
const express    = require("express");
const mongoose   = require("mongoose");
const bcrypt     = require("bcryptjs");
const session    = require("express-session");
const MongoStore = require("connect-mongo");
const cors       = require("cors");
const fetch      = (...a) => import("node-fetch").then(({default:f})=>f(...a));
const path       = require("path");

const app  = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/videohub";

/* ══════════════════════════════════
   DATABASE
══════════════════════════════════ */
mongoose.connect(MONGO_URI)
  .then(()=> console.log("✅ MongoDB connected"))
  .catch(err=> { console.error("❌ MongoDB error:", err); process.exit(1); });

/* ══════════════════════════════════
   SCHEMAS & MODELS
══════════════════════════════════ */

// User
const userSchema = new mongoose.Schema({
  username: { type:String, required:true, unique:true, trim:true, minlength:2, maxlength:30 },
  email:    { type:String, required:true, unique:true, trim:true, lowercase:true },
  password: { type:String, required:true },
  createdAt:{ type:Date, default:Date.now }
});

userSchema.pre("save", async function(next){
  if(!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = function(plain){
  return bcrypt.compare(plain, this.password);
};

const User = mongoose.model("User", userSchema);

// Video metadata (stores title/thumb so we don't lose it)
const videoSchema = new mongoose.Schema({
  videoId:   { type:String, required:true, unique:true }, // base64url of video_url
  videoUrl:  { type:String, required:true },
  title:     String,
  thumbnail: String,
  likeCount: { type:Number, default:0 },
  createdAt: { type:Date, default:Date.now }
});

const Video = mongoose.model("Video", videoSchema);

// Like (one per user per video)
const likeSchema = new mongoose.Schema({
  userId:   { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true },
  videoId:  { type:String, required:true },
  createdAt:{ type:Date, default:Date.now }
});
likeSchema.index({ userId:1, videoId:1 }, { unique:true });

const Like = mongoose.model("Like", likeSchema);

// Comment
const commentSchema = new mongoose.Schema({
  userId:   { type:mongoose.Schema.Types.ObjectId, ref:"User", required:true },
  username: String,
  videoId:  { type:String, required:true },
  text:     { type:String, required:true, maxlength:1000 },
  createdAt:{ type:Date, default:Date.now }
});

const Comment = mongoose.model("Comment", commentSchema);

/* ══════════════════════════════════
   MIDDLEWARE
══════════════════════════════════ */
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended:true }));

app.use(session({
  secret: process.env.SESSION_SECRET || "vhp-secret-change-me",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: MONGO_URI, ttl: 7 * 24 * 60 * 60 }),
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  }
}));

// Serve frontend
app.use(express.static(path.join(__dirname, "public")));

/* ══════════════════════════════════
   AUTH HELPER
══════════════════════════════════ */
function requireAuth(req, res, next){
  if(!req.session.userId) return res.status(401).json({ message:"Not authenticated" });
  next();
}

function safeUser(u){ return { _id:u._id, username:u.username, email:u.email }; }

/* ══════════════════════════════════
   AUTH ROUTES  /api/auth
══════════════════════════════════ */
const authRouter = express.Router();

// Register
authRouter.post("/register", async (req, res)=>{
  try{
    const { username, email, password } = req.body;
    if(!username||!email||!password) return res.status(400).json({ message:"All fields required." });
    if(password.length < 6) return res.status(400).json({ message:"Password must be at least 6 characters." });

    const exists = await User.findOne({ $or:[{email:email.toLowerCase()},{username}] });
    if(exists){
      if(exists.email===email.toLowerCase()) return res.status(409).json({ message:"Email already in use." });
      return res.status(409).json({ message:"Username already taken." });
    }

    const user = await User.create({ username, email, password });
    req.session.userId = user._id;
    res.status(201).json({ user: safeUser(user) });
  }catch(e){
    console.error(e);
    res.status(500).json({ message:"Server error." });
  }
});

// Login
authRouter.post("/login", async (req, res)=>{
  try{
    const { email, password } = req.body;
    if(!email||!password) return res.status(400).json({ message:"All fields required." });

    const user = await User.findOne({ email: email.toLowerCase() });
    if(!user) return res.status(401).json({ message:"Invalid email or password." });

    const match = await user.comparePassword(password);
    if(!match) return res.status(401).json({ message:"Invalid email or password." });

    req.session.userId = user._id;
    res.json({ user: safeUser(user) });
  }catch(e){
    console.error(e);
    res.status(500).json({ message:"Server error." });
  }
});

// Logout
authRouter.post("/logout", (req, res)=>{
  req.session.destroy(()=> res.json({ ok:true }));
});

// Me (check session)
authRouter.get("/me", async (req, res)=>{
  if(!req.session.userId) return res.status(401).json({ message:"Not authenticated" });
  try{
    const user = await User.findById(req.session.userId).select("-password");
    if(!user) return res.status(401).json({ message:"User not found" });
    res.json(safeUser(user));
  }catch(e){ res.status(500).json({ message:"Server error" }); }
});

app.use("/api/auth", authRouter);

/* ══════════════════════════════════
   VIDEO ROUTES  /api/videos
══════════════════════════════════ */
const videoRouter = express.Router();

// Helper — ensure video doc exists in DB
async function ensureVideo(videoId, body={}){
  let video = await Video.findOne({ videoId });
  if(!video){
    video = await Video.create({
      videoId,
      videoUrl:  body.videoUrl  || "",
      title:     body.videoTitle || "",
      thumbnail: body.videoThumb || ""
    });
  }
  return video;
}

// GET /api/videos/:videoId/likes
videoRouter.get("/:videoId/likes", async (req, res)=>{
  try{
    const { videoId } = req.params;
    const video = await Video.findOne({ videoId });
    const count = video ? video.likeCount : 0;

    let userLiked = false;
    if(req.session.userId){
      const like = await Like.findOne({ userId:req.session.userId, videoId });
      userLiked = !!like;
    }

    res.json({ count, userLiked });
  }catch(e){ res.status(500).json({ message:"Server error" }); }
});

// POST /api/videos/:videoId/like  (toggle)
videoRouter.post("/:videoId/like", requireAuth, async (req, res)=>{
  try{
    const { videoId } = req.params;
    const userId = req.session.userId;

    await ensureVideo(videoId, req.body);

    const existing = await Like.findOne({ userId, videoId });

    if(existing){
      await Like.deleteOne({ _id: existing._id });
      await Video.updateOne({ videoId }, { $inc:{ likeCount:-1 } });
      const video = await Video.findOne({ videoId });
      return res.json({ liked:false, count: Math.max(0, video.likeCount) });
    } else {
      await Like.create({ userId, videoId });
      await Video.updateOne({ videoId }, { $inc:{ likeCount:1 } });
      const video = await Video.findOne({ videoId });
      return res.json({ liked:true, count: video.likeCount });
    }
  }catch(e){ console.error(e); res.status(500).json({ message:"Server error" }); }
});

// GET /api/videos/:videoId/comments
videoRouter.get("/:videoId/comments", async (req, res)=>{
  try{
    const { videoId } = req.params;
    const comments = await Comment.find({ videoId }).sort({ createdAt:-1 }).limit(100);
    res.json({ comments });
  }catch(e){ res.status(500).json({ message:"Server error" }); }
});

// POST /api/videos/:videoId/comment
videoRouter.post("/:videoId/comment", requireAuth, async (req, res)=>{
  try{
    const { videoId } = req.params;
    const { text } = req.body;

    if(!text||!text.trim()) return res.status(400).json({ message:"Comment text required." });
    if(text.length > 1000) return res.status(400).json({ message:"Comment too long." });

    const user = await User.findById(req.session.userId).select("username");
    if(!user) return res.status(401).json({ message:"User not found." });

    await ensureVideo(videoId, req.body);

    const comment = await Comment.create({
      userId:   user._id,
      username: user.username,
      videoId,
      text:     text.trim()
    });

    res.status(201).json({ comment });
  }catch(e){ console.error(e); res.status(500).json({ message:"Server error" }); }
});

app.use("/api/videos", videoRouter);

/* ══════════════════════════════════
   PROXY ROUTES (your existing video API)
   /api/proxy?q=...&page=...
   /api/video?url=...
══════════════════════════════════ */

// Proxy search — forward to your real video source API
app.get("/api/proxy", async (req, res)=>{
  try{
    const { q="hot", page=1 } = req.query;
    const upstream = `${process.env.VIDEO_API_BASE || "https://your-video-api.com"}/search?q=${encodeURIComponent(q)}&page=${page}`;
    const r = await fetch(upstream, { headers:{ "User-Agent":"VideoHubPro/1.0" } });
    const data = await r.json();
    res.json(data);
  }catch(e){
    console.error("Proxy error:", e);
    res.status(502).json({ error:"Upstream API error", videos:[] });
  }
});

// Video stream proxy
app.get("/api/video", async (req, res)=>{
  try{
    const { url } = req.query;
    if(!url) return res.status(400).send("Missing url");
    const upstream = await fetch(decodeURIComponent(url));
    res.setHeader("Content-Type", upstream.headers.get("content-type") || "video/mp4");
    const cl = upstream.headers.get("content-length");
    if(cl) res.setHeader("Content-Length", cl);
    upstream.body.pipe(res);
  }catch(e){
    console.error("Video proxy error:", e);
    res.status(502).send("Video unavailable");
  }
});

/* ══════════════════════════════════
   CATCH-ALL → serve frontend
══════════════════════════════════ */
app.get("*", (req, res)=>{
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/* ══════════════════════════════════
   START
══════════════════════════════════ */
app.listen(PORT, ()=>{
  console.log(`🚀 Video Hub Pro running at http://localhost:${PORT}`);
  console.log(`📦 MongoDB: ${MONGO_URI}`);
});
