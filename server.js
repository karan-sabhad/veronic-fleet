require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT) || 3001;
const pool = process.env.DATABASE_URL ? new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' || process.env.DATABASE_URL.includes('supabase') ? { rejectUnauthorized: false } : false,
    max: Number(process.env.DB_POOL_MAX) || 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
}) : null;

app.use(cors({ origin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const query = (text, values = []) => {
    if (!pool) throw new Error('DATABASE_URL is not configured');
    return pool.query(text, values);
};
const one = async (text, values) => (await query(text, values)).rows[0] || null;
const many = async (text, values) => (await query(text, values)).rows;
const numericId = value => Number.isInteger(Number(value)) && Number(value) > 0 ? Number(value) : null;
const errorMessage = error => error.code === '23505' ? 'A record with that value already exists' : error.message;
function sendError(res, error, status = 500) { res.status(status).json({ error: errorMessage(error) }); }
async function withTransaction(work) {
    if (!pool) throw new Error('DATABASE_URL is not configured');
    const client = await pool.connect();
    try { await client.query('BEGIN'); const result = await work(client); await client.query('COMMIT'); return result; }
    catch (error) { await client.query('ROLLBACK'); throw error; }
    finally { client.release(); }
}

async function seedData() {
    if ((await one('SELECT COUNT(*)::int AS count FROM drivers')).count === 0) {
        const drivers = [['Vijay Odedra', '9510075279'], ['Vansh Rabari', '9876543210'], ['Ramesh Makwana', '9988776655'], ['vashu odedra', '9909989890'], ['vijay', '1234567890'], ['vashu', '456789123'], ['chirag', '124578963'], ['vivek', '2589648723']];
        await withTransaction(async client => {
            const ids = [];
            for (const [name, mobile] of drivers) ids.push((await client.query('INSERT INTO drivers(name,mobile) VALUES($1,$2) RETURNING id', [name, mobile])).rows[0].id);
            await client.query('INSERT INTO buses(bus_number,assigned_driver_id) VALUES($1,$2),($3,$4),($5,$6) ON CONFLICT DO NOTHING', ['GJ-01-LTZ1162', ids[2], 'GJ-01-LTZ1163', ids[7], 'GJ-01-LTZ1166', ids[6]]);
        });
    }
    if ((await one('SELECT COUNT(*)::int AS count FROM users')).count === 0) await query('INSERT INTO users(name,email,password) VALUES($1,$2,$3),($4,$5,$6),($7,$8,$9) ON CONFLICT DO NOTHING', ['Admin', 'admin@veronic.com', 'admin123', 'Demo User', 'demo@example.com', 'demo', 'Simple User', 'user@simple.com', '123']);
}
async function initializeDatabase() {
    if (!pool) { console.warn('DATABASE_URL is not configured; database routes will return 503'); return; }
    await query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
    await seedData();
    console.log('Connected to Supabase PostgreSQL and schema is ready');
}

const authToken = req => req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null;
const newToken = () => crypto.randomBytes(32).toString('hex');
const getSession = token => one("SELECT s.*,u.name,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=$1 AND s.expires_at>NOW()", [token]);
const findUser = (email, password) => one('SELECT * FROM users WHERE email=$1 AND password=$2', [email, password]);

app.get('/health', async (req, res) => { try { await query('SELECT 1'); res.json({ status: 'ok' }); } catch (error) { res.status(503).json({ status: 'unavailable', error: error.message }); } });
app.post('/api/signup', async (req, res) => { try { const { name, email, password } = req.body; if (!name || !email || !password) return res.status(400).json({ success: false, message: 'All fields are required' }); if (password.length < 3) return res.status(400).json({ success: false, message: 'Password must be at least 3 characters' }); const user = (await query('INSERT INTO users(name,email,password) VALUES($1,$2,$3) RETURNING id,name,email', [name.trim(), email.trim().toLowerCase(), password])).rows[0]; const token = newToken(); await query("INSERT INTO sessions(user_id,token,expires_at) VALUES($1,$2,NOW()+INTERVAL '7 days')", [user.id, token]); res.status(201).json({ success: true, message: 'Account created successfully', data: { user, token } }); } catch (error) { res.status(error.code === '23505' ? 409 : 500).json({ success: false, message: error.code === '23505' ? 'User already exists with this email' : 'Internal server error' }); } });
app.post('/api/login', async (req, res) => { try { const { email, password } = req.body; if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password are required' }); const user = await findUser(email.trim().toLowerCase(), password); if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials. Please check your email and password.' }); const token = newToken(); await query("INSERT INTO sessions(user_id,token,expires_at) VALUES($1,$2,NOW()+INTERVAL '7 days')", [user.id, token]); delete user.password; res.json({ success: true, message: 'Login successful', data: { user, token } }); } catch (error) { sendError(res, error); } });
app.post('/api/logout', async (req, res) => { try { if (!req.body.token) return res.status(400).json({ success: false, message: 'Token is required' }); await query('DELETE FROM sessions WHERE token=$1', [req.body.token]); res.json({ success: true, message: 'Logged out successfully' }); } catch (error) { sendError(res, error); } });
app.get('/api/verify', async (req, res) => { try { const current = await getSession(authToken(req)); if (!current) return res.status(401).json({ success: false, message: 'Invalid or expired session' }); res.json({ success: true, message: 'Session valid', data: { user: { id: current.user_id, name: current.name, email: current.email } } }); } catch (error) { sendError(res, error); } });
app.get('/api/profile', async (req, res) => { try { const current = await getSession(authToken(req)); if (!current) return res.status(401).json({ success: false, message: 'Invalid or expired session' }); res.json({ success: true, data: { user: await one('SELECT id,name,email,created_at FROM users WHERE id=$1', [current.user_id]) } }); } catch (error) { sendError(res, error); } });
app.get('/api/users/all', async (req, res) => { try { res.json({ success: true, data: { users: await many('SELECT id,name,email,created_at FROM users ORDER BY created_at DESC') } }); } catch (error) { sendError(res, error); } });
app.post('/api/check-user', async (req, res) => { try { res.json({ success: true, data: { exists: !!(await one('SELECT id FROM users WHERE email=$1', [req.body.email?.trim().toLowerCase()])) } }); } catch (error) { sendError(res, error); } });
app.put('/api/update-password', async (req, res) => { try { const current = await getSession(authToken(req)); if (!current) return res.status(401).json({ success: false, message: 'Invalid or expired session' }); if (!req.body.currentPassword || !req.body.newPassword || req.body.newPassword.length < 3) return res.status(400).json({ success: false, message: 'A valid current and new password are required' }); if (!(await findUser(current.email, req.body.currentPassword))) return res.status(401).json({ success: false, message: 'Current password is incorrect' }); await query('UPDATE users SET password=$1 WHERE id=$2', [req.body.newPassword, current.user_id]); res.json({ success: true, message: 'Password updated successfully' }); } catch (error) { sendError(res, error); } });
app.delete('/api/delete-account', async (req, res) => { try { const current = await getSession(authToken(req)); if (!current || !(await findUser(current.email, req.body.password))) return res.status(401).json({ success: false, message: 'Invalid session or password' }); await query('DELETE FROM users WHERE id=$1', [current.user_id]); res.json({ success: true, message: 'Account deleted successfully' }); } catch (error) { sendError(res, error); } });

function registerCrud(table, deletedTable, fields) {
    app.get(`/api/${table}`, async (req, res) => { try { const sql = table === 'buses' ? 'SELECT b.*,d.name AS driver_name FROM buses b LEFT JOIN drivers d ON d.id=b.assigned_driver_id ORDER BY b.bus_number' : `SELECT * FROM ${table} ORDER BY ${table === 'drivers' ? 'name' : 'created_at DESC'}`; res.json(await many(sql)); } catch (error) { sendError(res, error); } });
    app.get(`/api/deleted/${table}`, async (req, res) => { try { res.json(await many(`SELECT * FROM ${deletedTable} ORDER BY deleted_at DESC`)); } catch (error) { sendError(res, error); } });
    app.get(`/api/${table}/:id`, async (req, res) => { try { const sql = table === 'buses' ? 'SELECT b.*,d.name AS driver_name FROM buses b LEFT JOIN drivers d ON d.id=b.assigned_driver_id WHERE b.id=$1' : `SELECT * FROM ${table} WHERE id=$1`; const row = await one(sql, [numericId(req.params.id)]); if (!row) return res.status(404).json({ error: 'Record not found' }); res.json(row); } catch (error) { sendError(res, error); } });
    app.post(`/api/${table}`, async (req, res) => { try { const values = fields.map(f => req.body[f.key] ?? f.default ?? null); if (!values[0]) return res.status(400).json({ error: `${fields[0].label} is required` }); const result = await query(`INSERT INTO ${table}(${fields.map(f => f.column).join(',')}) VALUES(${values.map((_, i) => `$${i + 1}`).join(',')}) RETURNING *`, values); res.status(201).json(result.rows[0]); } catch (error) { sendError(res, error, error.code === '23505' ? 400 : 500); } });
    app.put(`/api/${table}/:id`, async (req, res) => { try { const values = fields.map(f => req.body[f.key] ?? f.default ?? null); if (!values[0]) return res.status(400).json({ error: `${fields[0].label} is required` }); const result = await query(`UPDATE ${table} SET ${fields.map((f, i) => `${f.column}=$${i + 1}`).join(',')} WHERE id=$${values.length + 1} RETURNING *`, [...values, numericId(req.params.id)]); if (!result.rowCount) return res.status(404).json({ error: 'Record not found' }); res.json(result.rows[0]); } catch (error) { sendError(res, error, error.code === '23505' ? 400 : 500); } });
    app.delete(`/api/${table}/:id`, async (req, res) => { try { const result = await withTransaction(async client => { const row = (await client.query(`SELECT * FROM ${table} WHERE id=$1`, [numericId(req.params.id)])).rows[0]; if (!row) return null; const columns = Object.keys(row).filter(k => k !== 'id'); await client.query(`INSERT INTO ${deletedTable}(${columns.join(',')},id) SELECT ${columns.join(',')},id FROM ${table} WHERE id=$1`, [row.id]); await client.query(`DELETE FROM ${table} WHERE id=$1`, [row.id]); return row; }); if (!result) return res.status(404).json({ error: 'Record not found' }); res.json({ message: 'Record moved to deleted records' }); } catch (error) { sendError(res, error); } });
}
registerCrud('drivers', 'deleted_drivers', [{ key: 'name', column: 'name', label: 'Name' }, { key: 'mobile', column: 'mobile', default: '' }]);
registerCrud('buses', 'deleted_buses', [{ key: 'busNumber', column: 'bus_number', label: 'Bus number' }, { key: 'assignedDriverId', column: 'assigned_driver_id', default: null }, { key: 'status', column: 'status', default: 'Active' }]);
app.get('/api/buses', async (req, res) => { try { res.json(await many('SELECT b.*,d.name AS driver_name FROM buses b LEFT JOIN drivers d ON d.id=b.assigned_driver_id ORDER BY b.bus_number')); } catch (error) { sendError(res, error); } });
app.get('/api/buses/:id', async (req, res) => { try { const row = await one('SELECT b.*,d.name AS driver_name FROM buses b LEFT JOIN drivers d ON d.id=b.assigned_driver_id WHERE b.id=$1', [numericId(req.params.id)]); if (!row) return res.status(404).json({ error: 'Bus not found' }); res.json(row); } catch (error) { sendError(res, error); } });
async function restore(table, deletedTable, req, res) { try { const row = await one(`SELECT * FROM ${deletedTable} WHERE id=$1`, [numericId(req.params.id)]); if (!row) return res.status(404).json({ error: 'Deleted record not found' }); const columns = Object.keys(row).filter(k => !['deleted_at', 'deleted_by'].includes(k)); const result = await query(`INSERT INTO ${table}(${columns.join(',')}) VALUES(${columns.map((_, i) => `$${i + 1}`).join(',')}) ON CONFLICT DO NOTHING RETURNING id`, columns.map(k => row[k])); if (!result.rowCount) return res.status(400).json({ error: 'Record conflicts with an active record' }); await query(`DELETE FROM ${deletedTable} WHERE id=$1`, [row.id]); res.json({ message: 'Record restored successfully', newId: result.rows[0].id }); } catch (error) { sendError(res, error); } }
app.post('/api/deleted/drivers/:id/restore', (req, res) => restore('drivers', 'deleted_drivers', req, res));
app.post('/api/deleted/buses/:id/restore', (req, res) => restore('buses', 'deleted_buses', req, res));

app.get('/api/today-drivers', async (req, res) => { try { res.json(await many('SELECT t.*,b.bus_number,d.name AS driver_name FROM today_driver_assignments t JOIN buses b ON b.id=t.bus_id JOIN drivers d ON d.id=t.driver_id WHERE t.assigned_date=CURRENT_DATE ORDER BY t.assigned_at')); } catch (error) { sendError(res, error); } });
app.post('/api/today-drivers', async (req, res) => { try { const bus = await one('SELECT id,bus_number FROM buses WHERE id=$1', [numericId(req.body.busId)]); const driver = await one('SELECT id,name FROM drivers WHERE id=$1', [numericId(req.body.driverId)]); if (!bus || !driver) return res.status(404).json({ success: false, message: 'Selected bus or driver not found.' }); const row = await one('INSERT INTO today_driver_assignments(bus_id,driver_id) VALUES($1,$2) RETURNING *', [bus.id, driver.id]); res.json({ success: true, ...row, bus_number: bus.bus_number, driver_name: driver.name }); } catch (error) { res.status(error.code === '23505' ? 400 : 500).json({ success: false, message: error.code === '23505' ? 'This bus or driver is already assigned today.' : error.message }); } });
app.delete('/api/today-drivers/:id', async (req, res) => { try { const result = await query('DELETE FROM today_driver_assignments WHERE id=$1', [numericId(req.params.id)]); if (!result.rowCount) return res.status(404).json({ success: false, message: 'Assignment not found.' }); res.json({ success: true, message: 'Assignment removed successfully.' }); } catch (error) { sendError(res, error); } });

const billValues = body => [body.date, body.driver, body.busNo, body.moklnar, body.moklnarMobile || '', body.lenar || 'N/A', body.lenarMobile || '', Number(body.total) || 0, Number(body.jama) || 0, Number(body.baki) || 0];
async function insertItems(client, billId, items = []) { for (const item of items) await client.query('INSERT INTO bill_items(bill_id,from_city,to_city,description,qty,remark,amount) VALUES($1,$2,$3,$4,$5,$6,$7)', [billId, item.from || 'Rajkot', item.to || 'Surat', item.desc || '', Number(item.qty) || 1, item.remark || '', Number(item.amount) || 0]); }
app.get('/api/bills', async (req, res) => { try { res.json(await many('SELECT * FROM bills ORDER BY created_at DESC')); } catch (error) { sendError(res, error); } });
app.get('/api/deleted/bills', async (req, res) => { try { res.json(await many('SELECT * FROM deleted_bills ORDER BY deleted_at DESC')); } catch (error) { sendError(res, error); } });
app.get('/api/bills/:id', async (req, res) => { try { const bill = await one('SELECT * FROM bills WHERE id=$1', [numericId(req.params.id)]); if (!bill) return res.status(404).json({ error: 'Bill not found' }); bill.items = await many('SELECT * FROM bill_items WHERE bill_id=$1', [bill.id]); res.json(bill); } catch (error) { sendError(res, error); } });
app.get('/api/bills/:id/items', async (req, res) => { try { res.json(await many('SELECT * FROM bill_items WHERE bill_id=$1', [numericId(req.params.id)])); } catch (error) { sendError(res, error); } });
app.get('/api/deleted/bills/:id/items', async (req, res) => { try { res.json(await many('SELECT * FROM deleted_bill_items WHERE bill_id=$1', [numericId(req.params.id)])); } catch (error) { sendError(res, error); } });
app.post('/api/bills', async (req, res) => { try { if (!req.body.billNo || !req.body.date || !req.body.driver || !req.body.busNo || !req.body.moklnar) return res.status(400).json({ error: 'Missing required fields' }); const result = await withTransaction(async client => { const values = [req.body.billNo, ...billValues(req.body)]; const bill = (await client.query('INSERT INTO bills(bill_no,date,driver_name,bus_no,moklnar_name,moklnar_mobile,lenar_name,lenar_mobile,total,jama,baki) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id', values)).rows[0]; await insertItems(client, bill.id, req.body.items); return bill; }); res.status(201).json({ id: result.id, message: 'Bill created successfully' }); } catch (error) { sendError(res, error, error.code === '23505' ? 400 : 500); } });
app.put('/api/bills/:id', async (req, res) => { try { const result = await withTransaction(async client => { const values = [...billValues(req.body), numericId(req.params.id)]; const bill = await client.query('UPDATE bills SET date=$1,driver_name=$2,bus_no=$3,moklnar_name=$4,moklnar_mobile=$5,lenar_name=$6,lenar_mobile=$7,total=$8,jama=$9,baki=$10 WHERE id=$11 RETURNING id', values); if (!bill.rowCount) return null; await client.query('DELETE FROM bill_items WHERE bill_id=$1', [numericId(req.params.id)]); await insertItems(client, numericId(req.params.id), req.body.items); return bill.rows[0]; }); if (!result) return res.status(404).json({ error: 'Bill not found' }); res.json({ message: 'Bill updated successfully' }); } catch (error) { sendError(res, error); } });
app.delete('/api/bills/:id', async (req, res) => { try { const result = await withTransaction(async client => { const bill = (await client.query('SELECT * FROM bills WHERE id=$1', [numericId(req.params.id)])).rows[0]; if (!bill) return null; const items = (await client.query('SELECT * FROM bill_items WHERE bill_id=$1', [bill.id])).rows; const billCols = Object.keys(bill).filter(k => k !== 'id'); await client.query(`INSERT INTO deleted_bills(${billCols.join(',')},id) SELECT ${billCols.join(',')},id FROM bills WHERE id=$1`, [bill.id]); for (const item of items) { const itemCols = Object.keys(item).filter(k => k !== 'id'); await client.query(`INSERT INTO deleted_bill_items(${itemCols.join(',')},id) SELECT ${itemCols.join(',')},id FROM bill_items WHERE id=$1`, [item.id]); } await client.query('DELETE FROM bills WHERE id=$1', [bill.id]); return bill; }); if (!result) return res.status(404).json({ error: 'Bill not found' }); res.json({ message: 'Bill moved to deleted records' }); } catch (error) { sendError(res, error); } });
app.post('/api/deleted/bills/:id/restore', async (req, res) => { try { const bill = await one('SELECT * FROM deleted_bills WHERE id=$1', [numericId(req.params.id)]); if (!bill) return res.status(404).json({ error: 'Deleted bill not found' }); const cols = Object.keys(bill).filter(k => !['deleted_at', 'deleted_by'].includes(k)); const restored = await withTransaction(async client => { const result = await client.query(`INSERT INTO bills(${cols.join(',')}) VALUES(${cols.map((_, i) => `$${i + 1}`).join(',')}) ON CONFLICT DO NOTHING RETURNING id`, cols.map(k => bill[k])); if (!result.rowCount) return null; const items = await client.query('SELECT * FROM deleted_bill_items WHERE bill_id=$1', [bill.id]); for (const item of items.rows) { const itemCols = Object.keys(item).filter(k => !['deleted_at', 'deleted_by'].includes(k)); await client.query(`INSERT INTO bill_items(${itemCols.join(',')}) VALUES(${itemCols.map((_, i) => `$${i + 1}`).join(',')}) ON CONFLICT DO NOTHING`, itemCols.map(k => k === 'bill_id' ? result.rows[0].id : item[k])); } await client.query('DELETE FROM deleted_bill_items WHERE bill_id=$1', [bill.id]); await client.query('DELETE FROM deleted_bills WHERE id=$1', [bill.id]); return result.rows[0]; }); if (!restored) return res.status(400).json({ error: 'Bill number already exists' }); res.json({ message: 'Bill restored successfully', newId: restored.id }); } catch (error) { sendError(res, error); } });
async function report(res, where, values) { try { const rows = await many(`SELECT b.*,bi.from_city,bi.to_city,bi.qty FROM bills b LEFT JOIN bill_items bi ON b.id=bi.bill_id WHERE ${where} ORDER BY b.created_at DESC`, values); const map = new Map(); for (const row of rows) { if (!map.has(row.id)) map.set(row.id, { id: row.id, bill_no: row.bill_no, date: row.date, driver_name: row.driver_name, bus_no: row.bus_no, moklnar_name: row.moklnar_name, lenar_name: row.lenar_name, total: row.total, jama: row.jama, baki: row.baki, items: [] }); if (row.from_city) map.get(row.id).items.push({ from_city: row.from_city, to_city: row.to_city, qty: row.qty }); } res.json([...map.values()]); } catch (error) { sendError(res, error); } }
app.get('/api/bills/date/:date', (req, res) => report(res, 'b.date=$1', [req.params.date]));
app.get('/api/bills/month/:month', (req, res) => report(res, "to_char(b.date,'YYYY-MM')=$1", [req.params.month]));
app.get('/api/stats', async (req, res) => { try { res.json(await one("SELECT (SELECT COUNT(*) FROM drivers)::int AS \"totalDrivers\",(SELECT COUNT(*) FROM bills WHERE date=CURRENT_DATE)::int AS \"todayBills\",COALESCE((SELECT SUM(total) FROM bills WHERE date>=date_trunc('month',CURRENT_DATE)),0) AS \"monthRevenue\",(SELECT COUNT(*) FROM buses WHERE status='Active')::int AS \"activeBuses\",(SELECT COUNT(*) FROM deleted_drivers)::int AS \"deletedDrivers\",(SELECT COUNT(*) FROM deleted_buses)::int AS \"deletedBuses\",(SELECT COUNT(*) FROM deleted_bills)::int AS \"deletedBills\"")); } catch (error) { sendError(res, error); } });

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((req, res) => res.status(404).json({ error: 'Route not found' }));
app.use((error, req, res, next) => { console.error(error); res.status(500).json({ error: 'Internal server error' }); });

initializeDatabase().catch(error => console.error('Database initialization failed:', error.message));
if (require.main === module) app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
module.exports = app;
