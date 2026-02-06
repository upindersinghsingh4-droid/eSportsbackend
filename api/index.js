const express = require('express');
const admin = require('firebase-admin');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');

// ==========================================
// CONFIGURATION & INITIALIZATION
// ==========================================

const firebaseServiceAccount = {
    "type": "service_account",
    "project_id": "YOUR_PROJECT_ID",
    "private_key": "YOUR_PRIVATE_KEY".replace(/\\n/g, '\n'),
    "client_email": "YOUR_CLIENT_EMAIL"
};

admin.initializeApp({
    credential: admin.credential.cert(firebaseServiceAccount)
});

const db = admin.firestore();
const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const CASHFREE_CONFIG = {
    appId: "YOUR_CASHFREE_APP_ID",
    secretKey: "YOUR_CASHFREE_SECRET_KEY",
    baseUrl: "https://api.cashfree.com/pg", // Use https://sandbox.cashfree.com/pg for testing
};

// ==========================================
// MIDDLEWARE: AUTHENTICATION
// ==========================================

const authenticate = async (req, res, next) => {
    const idToken = req.headers.authorization?.split('Bearer ')[1];
    if (!idToken) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        req.user = decodedToken;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

const adminOnly = async (req, res, next) => {
    // Admin check: either custom claim or hardcoded whitelist
    if (req.user.email === "admin123@gmail.com" || req.user.isAdmin === true) {
        next();
    } else {
        res.status(403).json({ error: 'Admin access required' });
    }
};

// ==========================================
// ENDPOINT: SIGNUP
// ==========================================

app.post('/auth/signup', authenticate, async (req, res) => {
    const { username, email, referralCode } = req.body;
    const uid = req.user.uid;

    try {
        const userRef = db.collection('users').doc(uid);
        const userDoc = await userRef.get();

        if (userDoc.exists) return res.json({ success: true, message: 'User exists' });

        const newReferralCode = uid.slice(-6).toUpperCase();
        
        const userData = {
            username,
            email,
            walletBalance: 0,
            totalXP: 0,
            joinedMatches: [],
            referralCode: newReferralCode,
            referredBy: referralCode || null,
            matchesPlayed: 0,
            totalKills: 0,
            dailyStreak: 0,
            isVIP: false,
            lastDailyReward: null,
            status: 'active',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        };

        await userRef.set(userData);
        res.json({ success: true, referralCode: newReferralCode });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// ENDPOINT: JOIN MATCH (TRANSACTIONAL)
// ==========================================

app.post('/match/join', authenticate, async (req, res) => {
    const { matchId, gameUids } = req.body; // gameUids: array [uid1, uid2...]
    const uid = req.user.uid;

    if (!Array.isArray(gameUids) || gameUids.length === 0) {
        return res.status(400).json({ error: 'Invalid Game UIDs' });
    }

    try {
        const result = await db.runTransaction(async (t) => {
            const matchRef = db.collection('matches').doc(matchId);
            const userRef = db.collection('users').doc(uid);
            const teamRef = matchRef.collection('teams').doc(uid);

            const matchDoc = await t.get(matchRef);
            const userDoc = await t.get(userRef);
            const teamDoc = await t.get(teamRef);

            if (!matchDoc.exists) throw new Error('Match not found');
            const matchData = matchDoc.data();

            if (matchData.status !== 'upcoming') throw new Error('Match is no longer open');
            if (matchData.joinedCount >= matchData.maxPlayers) throw new Error('Match is full');
            if (teamDoc.exists) throw new Error('Already joined this match');
            if (userDoc.data().walletBalance < matchData.entryFee) throw new Error('Insufficient balance');

            // Check if any provided gameUid is already taken in this match
            const teamsSnapshot = await matchRef.collection('teams').where('gameUids', 'array-contains-any', gameUids).get();
            if (!teamsSnapshot.empty) throw new Error('One or more Game UIDs already registered in this match');

            // Deduct Wallet
            t.update(userRef, {
                walletBalance: admin.firestore.FieldValue.increment(-matchData.entryFee),
                joinedMatches: admin.firestore.FieldValue.arrayUnion(matchId)
            });

            // Increment Count
            t.update(matchRef, {
                joinedCount: admin.firestore.FieldValue.increment(1)
            });

            // Create Team Group
            t.set(teamRef, {
                ownerUid: uid,
                ownerUsername: userDoc.data().username,
                gameUids: gameUids,
                joinedAt: admin.firestore.FieldValue.serverTimestamp()
            });

            // Log Transaction
            const transRef = db.collection('transactions').doc();
            t.set(transRef, {
                userId: uid,
                type: 'match_join',
                amount: matchData.entryFee,
                matchId: matchId,
                status: 'SUCCESS',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });

            return { success: true };
        });

        res.json(result);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// ENDPOINT: DAILY REWARDS
// ==========================================

app.post('/rewards/daily', authenticate, async (req, res) => {
    const uid = req.user.uid;
    const userRef = db.collection('users').doc(uid);

    try {
        await db.runTransaction(async (t) => {
            const userDoc = await t.get(userRef);
            const data = userDoc.data();
            const now = new Date();
            const lastReward = data.lastDailyReward ? data.lastDailyReward.toDate() : new Date(0);

            const hoursSince = (now - lastReward) / (1000 * 60 * 60);
            if (hoursSince < 24) throw new Error('Reward available in ' + (24 - hoursSince).toFixed(1) + ' hours');

            const rewardAmount = 5; // Example reward
            t.update(userRef, {
                walletBalance: admin.firestore.FieldValue.increment(rewardAmount),
                dailyStreak: admin.firestore.FieldValue.increment(1),
                lastDailyReward: admin.firestore.FieldValue.serverTimestamp()
            });

            const transRef = db.collection('transactions').doc();
            t.set(transRef, {
                userId: uid,
                type: 'daily_reward',
                amount: rewardAmount,
                status: 'SUCCESS',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.json({ success: true, message: 'Daily reward collected!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// ENDPOINT: WALLET WITHDRAWAL
// ==========================================

app.post('/wallet/withdraw', authenticate, async (req, res) => {
    const { amount, upiId } = req.body;
    const uid = req.user.uid;

    if (amount < 50) return res.status(400).json({ error: 'Minimum withdrawal is ₹50' });

    try {
        await db.runTransaction(async (t) => {
            const userRef = db.collection('users').doc(uid);
            const userDoc = await t.get(userRef);

            if (userDoc.data().walletBalance < amount) throw new Error('Insufficient balance');

            // Deduct immediately (Locked)
            t.update(userRef, {
                walletBalance: admin.firestore.FieldValue.increment(-amount)
            });

            const withdrawRef = db.collection('withdrawals').doc();
            t.set(withdrawRef, {
                userId: uid,
                amount,
                upiId,
                status: 'PENDING',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });

            const transRef = db.collection('transactions').doc();
            t.set(transRef, {
                userId: uid,
                type: 'withdrawal',
                amount,
                status: 'PENDING',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.json({ success: true, message: 'Withdrawal request submitted' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// ==========================================
// PAYMENT: CASHFREE - CREATE ORDER
// ==========================================

app.post('/wallet/createOrder', authenticate, async (req, res) => {
    const { amount } = req.body;
    const uid = req.user.uid;
    const orderId = `order_${Date.now()}_${uid.slice(-4)}`;

    try {
        const response = await axios.post(`${CASHFREE_CONFIG.baseUrl}/orders`, {
            order_id: orderId,
            order_amount: amount,
            order_currency: "INR",
            customer_details: {
                customer_id: uid,
                customer_email: req.user.email,
                customer_phone: "9999999999" // Placeholder
            }
        }, {
            headers: {
                'x-client-id': CASHFREE_CONFIG.appId,
                'x-client-secret': CASHFREE_CONFIG.secretKey,
                'x-api-version': '2022-09-01'
            }
        });

        // Store Pending Transaction
        await db.collection('transactions').doc(orderId).set({
            userId: uid,
            amount: parseFloat(amount),
            orderId: orderId,
            type: 'deposit',
            status: 'PENDING',
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ success: true, payment_session_id: response.data.payment_session_id });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create payment order' });
    }
});

// ==========================================
// WEBHOOK: CASHFREE VERIFICATION
// ==========================================

app.post('/webhook/cashfree', async (req, res) => {
    const signature = req.headers['x-webhook-signature'];
    const timestamp = req.headers['x-webhook-timestamp'];
    const rawBody = JSON.stringify(req.body);

    // Verify Signature (Cashfree V3 Webhook Logic)
    const data = timestamp + rawBody;
    const expectedSignature = crypto
        .createHmac('sha256', CASHFREE_CONFIG.secretKey)
        .update(data)
        .digest('base64');

    if (signature !== expectedSignature) {
        return res.status(400).send('Invalid Signature');
    }

    const { order, payment } = req.body.data;
    const orderId = order.order_id;
    const status = payment.payment_status;

    if (status === 'SUCCESS') {
        try {
            await db.runTransaction(async (t) => {
                const transRef = db.collection('transactions').doc(orderId);
                const transDoc = await t.get(transRef);

                if (!transDoc.exists || transDoc.data().status === 'SUCCESS') return;

                const userId = transDoc.data().userId;
                const userRef = db.collection('users').doc(userId);

                t.update(userRef, {
                    walletBalance: admin.firestore.FieldValue.increment(transDoc.data().amount)
                });

                t.update(transRef, {
                    status: 'SUCCESS',
                    cf_payment_id: payment.cf_payment_id
                });
            });
        } catch (e) { console.error('Webhook processing failed', e); }
    }

    res.status(200).send('OK');
});

// ==========================================
// ADMIN: MATCH RESULT DISTRIBUTION
// ==========================================

app.post('/admin/match/distribute', authenticate, adminOnly, async (req, res) => {
    const { matchId, gameUid, rank, kills } = req.body;

    try {
        const matchRef = db.collection('matches').doc(matchId);
        const matchDoc = await matchRef.get();
        const matchData = matchDoc.data();

        if (matchData.prizeDistributed) return res.status(400).json({ error: 'Already distributed' });

        // Identify Team Owner
        const teamQuery = await matchRef.collection('teams').where('gameUids', 'array-contains', gameUid).limit(1).get();
        if (teamQuery.empty) return res.status(404).json({ error: 'Team not found for this Game UID' });

        const teamData = teamQuery.docs[0].data();
        const ownerUid = teamData.ownerUid;

        const rankPrize = matchData.rankPrizes[rank] || 0;
        const killPrize = kills * (matchData.perKillRate || 0);
        const totalPrize = rankPrize + killPrize;
        const xpGained = (rank === 1 ? 500 : 100) + (kills * 50);

        await db.runTransaction(async (t) => {
            const userRef = db.collection('users').doc(ownerUid);
            
            t.update(userRef, {
                walletBalance: admin.firestore.FieldValue.increment(totalPrize),
                totalXP: admin.firestore.FieldValue.increment(xpGained),
                matchesPlayed: admin.firestore.FieldValue.increment(1),
                totalKills: admin.firestore.FieldValue.increment(kills)
            });

            // Mark Match (Optional: usually done when ALL results are in, but per prompt criteria:)
            // We log the prize distribution for this specific team to prevent double crediting if same UID is used twice
            const resultRef = matchRef.collection('results').doc(gameUid);
            t.set(resultRef, {
                ownerUid,
                gameUid,
                rank,
                kills,
                prize: totalPrize,
                xp: xpGained,
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });

            const transRef = db.collection('transactions').doc();
            t.set(transRef, {
                userId: ownerUid,
                type: 'match_prize',
                amount: totalPrize,
                matchId: matchId,
                status: 'SUCCESS',
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
        });

        res.json({ success: true, prize: totalPrize, xp: xpGained });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==========================================
// START SERVER
// ==========================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Esports Backend running on port ${PORT}`);
});
