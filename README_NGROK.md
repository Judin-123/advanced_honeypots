# 🍯 Adaptive Honeypot with Ngrok - Quick Start Guide

## 🚀 Super Quick Start (One-Click)

**Just double-click:** `quick_start_ngrok.bat`

That's it! The script will:
1. Check if ngrok is installed
2. Help you install it if needed
3. Setup authentication
4. Start your honeypot
5. Create a public URL
6. Open everything in your browser

## 📋 Manual Setup (If you prefer step-by-step)

### Step 1: Install Ngrok
1. Go to https://ngrok.com/download
2. Download ngrok for Windows
3. Extract `ngrok.exe` to a folder
4. Add to PATH or copy to `C:\Windows\System32\`

### Step 2: Get Ngrok Account (Free)
1. Sign up at https://dashboard.ngrok.com/signup
2. Get your authtoken from https://dashboard.ngrok.com/get-started/your-authtoken
3. Run: `ngrok config add-authtoken YOUR_TOKEN`

### Step 3: Start Honeypot
```bash
# Option A: Use the setup script
python ngrok_honeypot_setup.py

# Option B: Manual start
python integrated_adaptive_dashboard.py
# In another terminal:
ngrok http 5003
```

## 🎯 What You Get

### 🧠 Adaptive Intelligence
- **4 Profiles**: Minimal → Standard → Aggressive → Deceptive
- **ML Analysis**: Uses your real CICIDS 2017 models (99.91% accuracy)
- **Auto-Adaptation**: Changes behavior based on attack patterns
- **Smart Deception**: Creates fake files, databases, SSH keys

### 🌍 Public Access
- **Instant URL**: Get a public URL like `https://abc123.ngrok.io`
- **Real Hackers**: Share the URL to attract actual attackers
- **Live Monitoring**: Watch attacks happen in real-time
- **Auto-Blocking**: Automatically blocks malicious IPs

### 📊 Beautiful Dashboard
- **Real-time Stats**: Live session and threat monitoring
- **ML Performance**: Shows your actual model accuracy
- **Adaptive Controls**: Manually switch profiles
- **Glass Design**: Modern, professional interface

## 🎭 How It Adapts

The honeypot automatically switches profiles based on attack patterns:

| Attack Pattern | Profile | Response |
|---|---|---|
| Low activity (< 5 attacks/hour) | **Minimal** | Basic SSH honeypot |
| Normal activity | **Standard** | SSH + HTTP + FTP |
| Heavy attacks (> 50/hour) | **Aggressive** | All services + fast blocking |
| Distributed attacks (> 10 IPs) | **Deceptive** | Maximum fake content |

## 🔒 Security Features

- **Real IP Blocking**: Uses Windows Firewall to actually block threats
- **ML Threat Detection**: 99.91% accuracy threat classification
- **Fake Content Generation**: Creates convincing fake files and databases
- **Session Analysis**: Tracks attacker behavior patterns
- **Automatic Adaptation**: Responds intelligently to attack types

## 📱 Monitoring Your Honeypot

### Dashboard URLs (when running):
- **Honeypot Dashboard**: Your ngrok URL (e.g., `https://abc123.ngrok.io`)
- **Ngrok Admin**: http://localhost:4040
- **Local Dashboard**: http://localhost:5003

### What to Watch:
1. **Total Sessions**: Real connections to your honeypot
2. **Threats Detected**: ML-classified malicious activity
3. **IPs Blocked**: Automatically blocked attackers
4. **Current Profile**: Adaptive behavior mode

## 🎯 Attracting Real Hackers

### Share Your URL:
1. **Security Forums**: Post in cybersecurity communities
2. **Social Media**: Share on Twitter, LinkedIn with security hashtags
3. **Shodan**: Your IP will appear in Shodan scans
4. **Port Scanners**: Automated scanners will find you
5. **Honeypot Lists**: Some attackers target known honeypot ranges

### Make It Attractive:
- **Fake Banners**: Shows fake SSH/HTTP server versions
- **Fake Vulnerabilities**: Appears to have security holes
- **Fake Content**: Creates tempting files like `passwords.txt`
- **Realistic Responses**: Behaves like a real vulnerable server

## 🛠 Troubleshooting

### Ngrok Issues:
```bash
# Check if ngrok is installed
ngrok version

# Re-authenticate
ngrok config add-authtoken YOUR_TOKEN

# Check tunnel status
curl http://localhost:4040/api/tunnels
```

### Honeypot Issues:
```bash
# Check if running
netstat -an | findstr :5003

# Restart honeypot
python integrated_adaptive_dashboard.py
```

### No Attacks Coming:
- Make sure your ngrok URL is publicly accessible
- Share the URL in security communities
- Wait - it can take hours or days for scanners to find you
- Check ngrok dashboard for any connection attempts

## 📊 Understanding the Data

### Session Types:
- **Legitimate**: Normal connections (rare)
- **Scanning**: Port scans and service detection
- **Brute Force**: Login attempts with common passwords
- **Exploitation**: Attempts to exploit fake vulnerabilities

### Threat Levels:
- **Low (0-30%)**: Probably legitimate or basic scanning
- **Medium (30-70%)**: Suspicious activity, monitoring
- **High (70-90%)**: Likely malicious, increased monitoring
- **Critical (90%+)**: Definitely malicious, immediate blocking

## 🎉 Success Indicators

You'll know it's working when you see:
- ✅ Sessions appearing in the dashboard
- ✅ ML threat scores being calculated
- ✅ IPs getting blocked automatically
- ✅ Profile adaptations happening
- ✅ Fake content being accessed

## 🆘 Getting Help

If you need help:
1. Check the console output for error messages
2. Verify ngrok is properly authenticated
3. Make sure Python dependencies are installed
4. Check Windows Firewall isn't blocking the honeypot
5. Ensure your ML models are in the `trained_models/` folder

## 🎯 Next Steps

Once your honeypot is running:
1. **Monitor Regularly**: Check the dashboard daily
2. **Analyze Patterns**: Look for attack trends
3. **Share Results**: Document interesting attacks
4. **Improve Deception**: Add more fake content
5. **Scale Up**: Consider multiple honeypots

---

**⚠️ Legal Notice**: Only deploy honeypots on networks you own or have permission to monitor. Check local laws regarding honeypot deployment and data collection.

**🛡️ Safety Note**: This honeypot is designed to be attacked. Only run it in isolated environments and monitor it regularly.