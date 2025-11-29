// 基础依赖
require('dotenv').config();          // ① 最先加载 env
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));             // 替代 bodyParser
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// 生成本地默认头像（不依赖外部 API）
const generateDefaultAvatar = (seed) => {
  const colors = [
    '#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', 
    '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2'
  ];
  const colorIndex = (seed || '').charCodeAt(0) % colors.length;
  const color = colors[colorIndex];
  const initial = (seed || 'U').charAt(0).toUpperCase();
  
  const svg = `
    <svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
      <rect width="100" height="100" fill="${color}"/>
      <text x="50" y="50" font-family="Arial" font-size="40" fill="white" 
            text-anchor="middle" dominant-baseline="central" font-weight="bold">${initial}</text>
    </svg>
  `.trim();
  return 'data:image/svg+xml;base64,' + Buffer.from(svg).toString('base64');
};

const DEFAULT_COVER =
  'https://images.unsplash.com/photo-1521587760476-6c12a4b040da?auto=format&fit=crop&w=600&q=80';

const deriveBookStatus = (total, available) => {
  if (Number(total) <= 0) return 'available';
  if (Number(available) <= 0) return 'borrowed';
  if (Number(available) >= Number(total)) return 'available';
  return 'partial';
};

// ② 数据库连接池
const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});

async function ensureSchema() {
  try {
    // 检查并添加 users 表的列
    const [userCols] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'`
    );
    const userColNames = userCols.map(c => c.COLUMN_NAME);
    
    if (!userColNames.includes('avatar_url')) {
      await pool.query('ALTER TABLE users ADD COLUMN avatar_url LONGTEXT');
      console.log('✅ Added avatar_url to users table');
    }
    if (!userColNames.includes('nickname')) {
      await pool.query('ALTER TABLE users ADD COLUMN nickname VARCHAR(100)');
      console.log('✅ Added nickname to users table');
    }
    if (!userColNames.includes('email')) {
      await pool.query('ALTER TABLE users ADD COLUMN email VARCHAR(120)');
      console.log('✅ Added email to users table');
    }
    if (!userColNames.includes('phone')) {
      await pool.query('ALTER TABLE users ADD COLUMN phone VARCHAR(40)');
      console.log('✅ Added phone to users table');
    }
    try {
      await pool.query('ALTER TABLE users MODIFY COLUMN avatar_url LONGTEXT');
      console.log('✅ Ensured avatar_url is LONGTEXT');
    } catch (err) {
      console.warn('⚠️  Could not modify users.avatar_url:', err.message);
    }

    // 检查并添加 books 表的列
    const [bookCols] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'books'`
    );
    const bookColNames = bookCols.map(c => c.COLUMN_NAME);
    
    if (!bookColNames.includes('cover_url')) {
      await pool.query('ALTER TABLE books ADD COLUMN cover_url LONGTEXT');
      console.log('✅ Added cover_url to books table');
    }
    if (!bookColNames.includes('description')) {
      await pool.query('ALTER TABLE books ADD COLUMN description TEXT');
      console.log('✅ Added description to books table');
    }
    if (!bookColNames.includes('available')) {
      await pool.query('ALTER TABLE books ADD COLUMN available INT DEFAULT 1');
      console.log('✅ Added available to books table');
    }
    if (!bookColNames.includes('price')) {
      await pool.query('ALTER TABLE books ADD COLUMN price DECIMAL(10,2) DEFAULT 0');
      console.log('✅ Added price to books table');
    }
    if (!bookColNames.includes('stock_total')) {
      await pool.query('ALTER TABLE books ADD COLUMN stock_total INT DEFAULT 0');
      console.log('✅ Added stock_total to books table');
    }
    if (!bookColNames.includes('stock_available')) {
      await pool.query('ALTER TABLE books ADD COLUMN stock_available INT DEFAULT 0');
      console.log('✅ Added stock_available to books table');
    }
    try {
      await pool.query('ALTER TABLE books MODIFY COLUMN cover_url LONGTEXT');
      console.log('✅ Ensured books.cover_url is LONGTEXT');
    } catch (err) {
      console.warn('⚠️  Could not modify books.cover_url:', err.message);
    }

    // 尝试修改 books 表的 status 列（如果失败不影响）
    // 需要先检查当前列类型，如果是 ENUM 类型，需要更特殊处理
    try {
      // 获取当前列信息
      const [colInfo] = await pool.query(
        `SELECT DATA_TYPE, COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS 
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'books' AND COLUMN_NAME = 'status'`
      );
      
      if (colInfo.length > 0) {
        const dataType = colInfo[0].DATA_TYPE;
        const columnType = colInfo[0].COLUMN_TYPE;
        
        // 如果是 ENUM 类型或 VARCHAR 长度不够，需要修改
        if (dataType === 'enum' || (dataType === 'varchar' && columnType.includes('(') && parseInt(columnType.match(/\((\d+)\)/)?.[1] || '0') < 20)) {
          // 尝试直接修改为 VARCHAR(20)
          await pool.query('ALTER TABLE books MODIFY COLUMN status VARCHAR(20) DEFAULT "available"');
          console.log('✅ Updated books.status to VARCHAR(20)');
        } else {
          console.log('✅ books.status column type is already correct:', columnType);
        }
      } else {
        // 如果列不存在，创建它
        await pool.query('ALTER TABLE books ADD COLUMN status VARCHAR(20) DEFAULT "available"');
        console.log('✅ Added books.status column');
      }
    } catch (err) {
      console.warn('⚠️  Could not modify books.status:', err.message);
      // 尝试另一种方式：如果失败，尝试先删除再添加
      try {
        await pool.query('ALTER TABLE books CHANGE COLUMN status status VARCHAR(20) DEFAULT "available"');
        console.log('✅ Updated books.status using CHANGE COLUMN');
      } catch (err2) {
        console.warn('⚠️  Could not modify books.status using CHANGE COLUMN:', err2.message);
      }
    }

    // 尝试修改 borrow 表的列（如果失败不影响）
    // 检查 borrow 表是否存在
    try {
      const [borrowTable] = await pool.query(
        `SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES 
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'borrow'`
      );
      if (borrowTable.length > 0) {
        // 检查 status 列是否存在
        const [borrowCols] = await pool.query(
          `SELECT COLUMN_NAME, DATA_TYPE, COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS 
           WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'borrow'`
        );
        const borrowColNames = borrowCols.map(c => c.COLUMN_NAME);
        const borrowColMap = new Map(borrowCols.map(c => [c.COLUMN_NAME, { DATA_TYPE: c.DATA_TYPE, COLUMN_TYPE: c.COLUMN_TYPE }]));

        // 修改 status 列
        if (borrowColNames.includes('status')) {
          const colInfo = borrowColMap.get('status');
          const dataType = colInfo.DATA_TYPE;
          // 如果是 ENUM，确保包含 'borrowed' 和 'returned'
          if (dataType === 'enum') {
            await pool.query(`ALTER TABLE borrow MODIFY COLUMN status ENUM('borrowed','returned') DEFAULT 'borrowed'`);
            console.log('✅ Updated borrow.status enum');
          } else {
            // 如果不是 ENUM，改为 ENUM
            await pool.query(`ALTER TABLE borrow MODIFY COLUMN status ENUM('borrowed','returned') DEFAULT 'borrowed'`);
            console.log('✅ Updated borrow.status to ENUM');
          }
        } else {
          // 如果列不存在，添加它
          await pool.query(`ALTER TABLE borrow ADD COLUMN status ENUM('borrowed','returned') DEFAULT 'borrowed'`);
          console.log('✅ Added borrow.status column');
        }

        // 修改 borrow_date 列，确保是 DATETIME 类型
        if (borrowColNames.includes('borrow_date')) {
          const colInfo = borrowColMap.get('borrow_date');
          const dataType = colInfo.DATA_TYPE;
          if (dataType === 'date' || dataType !== 'datetime' && dataType !== 'timestamp') {
            await pool.query('ALTER TABLE borrow MODIFY COLUMN borrow_date DATETIME');
            console.log('✅ Updated borrow.borrow_date to DATETIME');
          } else {
            console.log('✅ borrow.borrow_date is already DATETIME');
          }
        } else {
          await pool.query('ALTER TABLE borrow ADD COLUMN borrow_date DATETIME');
          console.log('✅ Added borrow.borrow_date column');
        }

        // 修改 return_date 列，确保是 DATETIME 类型
        if (borrowColNames.includes('return_date')) {
          const colInfo = borrowColMap.get('return_date');
          const dataType = colInfo.DATA_TYPE;
          if (dataType === 'date' || dataType !== 'datetime' && dataType !== 'timestamp') {
            await pool.query('ALTER TABLE borrow MODIFY COLUMN return_date DATETIME');
            console.log('✅ Updated borrow.return_date to DATETIME');
          } else {
            console.log('✅ borrow.return_date is already DATETIME');
          }
        } else {
          await pool.query('ALTER TABLE borrow ADD COLUMN return_date DATETIME DEFAULT NULL');
          console.log('✅ Added borrow.return_date column');
        }
      }
    } catch (err) {
      console.warn('⚠️  Could not modify borrow table columns:', err.message);
    }

    console.log('✅ Database schema check completed');
  } catch (err) {
    console.error('❌ Schema sync error:', err.message);
  }
}
ensureSchema();

const formatUser = (row) => ({
  id: row.id,
  username: row.username,
  role: row.role,
  avatar: row.avatar_url || generateDefaultAvatar(row.username),
  nickname: row.nickname || row.username,
  email: row.email || null,
});

const formatBook = (row) => {
  const total = Number(row.stock_total ?? row.total ?? row.available ?? 0);
  const available = Number(row.stock_available ?? row.available ?? total);
  return {
    ...row,
    price: Number(row.price ?? 0),
    stock_total: total,
    stock_available: available,
    cover_url: row.cover_url || DEFAULT_COVER,
    status: deriveBookStatus(total, available),
  };
};

// ④ 公共接口（无需登录）
app.get('/', (_req, res) => res.send('Server is up!'));

app.get('/test-db', async (_req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 + 1 AS result');
    res.json({ db_ok: true, result: rows[0].result });
  } catch (e) {
    res.status(500).json({ db_ok: false, error: e.message });
  }
});

// 注册
app.post('/register', async (req, res) => {
  try {
    const { username, password, avatar_url, nickname, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: '缺少字段' });

    // 检查用户名是否已存在
    const [[exist]] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
    if (exist) return res.status(400).json({ error: '用户名已存在' });

    // 确保 schema 已更新
    await ensureSchema();

    // 检查列是否存在，动态构建 INSERT 语句
    const [userCols] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'`
    );
    const userColNames = userCols.map(c => c.COLUMN_NAME);
    const hasAvatar = userColNames.includes('avatar_url');
    const hasNickname = userColNames.includes('nickname');

    const hash = await bcrypt.hash(password, 10);
    const userRole = role === 'admin' ? 'admin' : 'user';
    
    // 生成默认头像（使用本地方案，不依赖外部 API）
    const avatarValue = avatar_url || generateDefaultAvatar(username);
    const nicknameValue = nickname || username;

    if (hasAvatar && hasNickname) {
      // 完整版本：包含 avatar_url 和 nickname
      const [result] = await pool.query(
        'INSERT INTO users (username, password, role, avatar_url, nickname) VALUES (?, ?, ?, ?, ?)',
        [username, hash, userRole, avatarValue, nicknameValue]
      );
      res.json({ success: true, id: result.insertId });
    } else if (hasAvatar) {
      // 只有 avatar_url
      const [result] = await pool.query(
        'INSERT INTO users (username, password, role, avatar_url) VALUES (?, ?, ?, ?)',
        [username, hash, userRole, avatarValue]
      );
      res.json({ success: true, id: result.insertId });
    } else if (hasNickname) {
      // 只有 nickname
      const [result] = await pool.query(
        'INSERT INTO users (username, password, role, nickname) VALUES (?, ?, ?, ?)',
        [username, hash, userRole, nicknameValue]
      );
      res.json({ success: true, id: result.insertId });
    } else {
      // 基础版本：只有基本字段
      const [result] = await pool.query(
        'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
        [username, hash, userRole]
      );
      res.json({ success: true, id: result.insertId });
    }
  } catch (e) {
    console.error('[/register] 错误:', e);
    res.status(500).json({ error: e.message });
  }
});


// 登录（含排查日志）
app.post('/login', async (req, res) => {
  try {
    /* ===== 排查专用日志 ===== */
    console.log('[/login] 收到的 body:', req.body);
    /* ======================= */

    const { username, password } = req.body;
    const [[user]] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) return res.status(401).json({ error: '用户名或密码错误' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: '用户名或密码错误' });

    // 将用户名（username）添加到 JWT 的 payload 中
    const payload = { id: user.id, username: user.username, role: user.role };
    const token = createJWT(payload);  // 使用包含 username 的 payload 生成 token

    return res.json({
      success: true,
      token,
      user: formatUser(user),
    });
  } catch (e) {
    console.error('[/login] 异常:', e);   // 也把异常打出来
    res.status(500).json({ error: e.message });
  }
});

const createJWT = (payload) =>
  jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });

// ⑤ 鉴权中间件
const auth = require('./middleware/auth');   // 刚刚写的文件
const admin = require('./middleware/admin');
app.use('/api', auth);                       // 所有 /api/* 都需要登录

app.get('/api/me', async (req, res) => {
  try {
    // 检查列是否存在
    const [cols] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'`
    );
    const colNames = cols.map(c => c.COLUMN_NAME);
    
    // 动态构建 SELECT 语句
    const fields = ['id', 'username', 'role'];
    if (colNames.includes('avatar_url')) fields.push('avatar_url');
    if (colNames.includes('nickname')) fields.push('nickname');
    if (colNames.includes('email')) fields.push('email');
    if (colNames.includes('phone')) fields.push('phone');
    
    const [[user]] = await pool.query(
      `SELECT ${fields.join(', ')} FROM users WHERE id = ?`,
      [req.user.id]
    );
    
    if (!user) return res.status(404).json({ error: '用户不存在' });
    
    res.json({
      ...formatUser(user),
      email: user.email || null,
      phone: user.phone || null,
    });
  } catch (e) {
    console.error('[/api/me] GET 错误:', e);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/me', async (req, res) => {
  try {
    const { avatar, nickname, email, phone } = req.body;
    
    // 检查列是否存在
    const [cols] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'`
    );
    const colNames = cols.map(c => c.COLUMN_NAME);
    const hasAvatar = colNames.includes('avatar_url');
    const hasNickname = colNames.includes('nickname');
    const hasEmail = colNames.includes('email');
    const hasPhone = colNames.includes('phone');

    const avatarValue = avatar || generateDefaultAvatar(req.user.username);
    const nicknameValue = nickname || req.user.username;

    if (hasAvatar && hasNickname && hasEmail && hasPhone) {
      await pool.query(
        'UPDATE users SET avatar_url = ?, nickname = ?, email = ?, phone = ? WHERE id = ?',
        [avatarValue, nicknameValue, email || null, phone || null, req.user.id]
      );
    } else if (hasAvatar && hasNickname) {
      await pool.query(
        'UPDATE users SET avatar_url = ?, nickname = ? WHERE id = ?',
        [avatarValue, nicknameValue, req.user.id]
      );
    } else if (hasAvatar) {
      await pool.query(
        'UPDATE users SET avatar_url = ? WHERE id = ?',
        [avatarValue, req.user.id]
      );
    } else if (hasNickname) {
      await pool.query(
        'UPDATE users SET nickname = ? WHERE id = ?',
        [nicknameValue, req.user.id]
      );
    }
    res.json({ success: true });
  } catch (e) {
    console.error('[/api/me] PUT 错误:', e);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/me/password', async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: '缺少密码参数' });
    }
    const [[user]] = await pool.query('SELECT password FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    const ok = await bcrypt.compare(currentPassword, user.password);
    if (!ok) return res.status(400).json({ error: '原密码不正确' });
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = ? WHERE id = ?', [hash, req.user.id]);
    res.json({ success: true });
  } catch (e) {
    console.error('[/api/me/password] 错误:', e);
    res.status(500).json({ error: e.message });
  }
});

const borrowBook = async ({ bookId, userId }) => {
  const conn = await pool.getConnection();
  await conn.beginTransaction();
  try {
    // 检查用户是否已经借阅了这本书且未归还
    const [existingBorrows] = await conn.query(
      'SELECT id FROM borrow WHERE book_id = ? AND user_id = ? AND status = ?',
      [bookId, userId, 'borrowed']
    );
    if (existingBorrows.length > 0) {
      throw new Error('您已经借阅了这本书，请先归还后再借阅');
    }

    const [[book]] = await conn.query(
      'SELECT id, status, stock_total, stock_available, available FROM books WHERE id = ? FOR UPDATE',
      [bookId]
    );
    if (!book) throw new Error('图书不存在');

    const total = Number(book.stock_total ?? 0);
    let currentAvailable = Number(book.stock_available ?? 0);
    
    // 如果 stock_available 为 null 或 0，尝试从 available 字段获取
    if (currentAvailable === 0 && book.available !== null && book.available !== undefined) {
      currentAvailable = Number(book.available);
    }
    
    // 如果还是 0，且 total > 0，则初始化为 total
    if (currentAvailable === 0 && total > 0) {
      currentAvailable = total;
    }
    
    if (currentAvailable <= 0) {
      throw new Error('图书库存不足，无法借阅');
    }

    await conn.query(
      'INSERT INTO borrow (book_id, user_id, borrow_date, status) VALUES (?, ?, NOW(), ?)',
      [bookId, userId, 'borrowed']
    );

    const nextAvailable = currentAvailable - 1;
    const bookStatus = deriveBookStatus(total, nextAvailable);

    // 确保 status 值有效，如果无效则使用默认值
    const validStatus = ['available', 'borrowed', 'partial'].includes(bookStatus) ? bookStatus : 'available';

    await conn.query(
      `UPDATE books
         SET status = ?,
             stock_available = ?,
             available = CASE WHEN available IS NULL THEN NULL ELSE GREATEST(available - 1, 0) END
       WHERE id = ?`,
      [validStatus, nextAvailable, bookId]
    );
    await conn.commit();
    return { success: true };
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
};

const returnBook = async ({ borrowId }) => {
  const conn = await pool.getConnection();
  await conn.beginTransaction();
  try {
    const [[row]] = await conn.query(
      'SELECT book_id FROM borrow WHERE id = ? AND status = ? FOR UPDATE',
      [borrowId, 'borrowed']
    );
    if (!row) throw new Error('记录不存在或已归还');

    const [[book]] = await conn.query(
      'SELECT id, stock_total, stock_available, available FROM books WHERE id = ? FOR UPDATE',
      [row.book_id]
    );

    await conn.query(
      'UPDATE borrow SET return_date = NOW(), status = ? WHERE id = ?',
      ['returned', borrowId]
    );

    const total = Number(book?.stock_total ?? 0);
    const currentAvailable = Number(book?.stock_available ?? book?.available ?? 0);
    const nextAvailable =
      total > 0 ? Math.min(currentAvailable + 1, total) : currentAvailable + 1;
    const bookStatus = deriveBookStatus(total, nextAvailable);

    // 确保 status 值有效，如果无效则使用默认值
    const validStatus = ['available', 'borrowed', 'partial'].includes(bookStatus) ? bookStatus : 'available';

    await conn.query(
      `UPDATE books
         SET status = ?,
             stock_available = ?,
             available = CASE WHEN available IS NULL THEN NULL ELSE available + 1 END
       WHERE id = ?`,
      [validStatus, nextAvailable, row.book_id]
    );
    await conn.commit();
    return { success: true };
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
};

// ⑥ 受保护的业务路由（统一加 /api 前缀，方便代理）
// 图书
app.get('/api/books', async (_req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM books ORDER BY id DESC');
    res.json((rows || []).map(formatBook));
  } catch (e) {
    console.error('[/api/books] 错误:', e);
    res.status(500).json({ error: e.message });
  }
});
app.post('/api/books', admin, async (req, res) => {
  const {
    title,
    author,
    publish_date,
    cover_url,
    cover_data,
    description,
    price,
    stock_total,
    stock_available,
  } = req.body;

  const total = Number(stock_total ?? 0);
  const available = Number(
    stock_available !== undefined ? stock_available : stock_total ?? 0
  );
  const normalizedAvailable = Math.min(Math.max(available, 0), Math.max(total, 0));
  const status = deriveBookStatus(total, normalizedAvailable);

  await pool.query(
    `INSERT INTO books
      (title, author, publish_date, status, cover_url, description, price, stock_total, stock_available)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      title,
      author,
      publish_date,
      status,
      cover_data || cover_url || DEFAULT_COVER,
      description || null,
      Number(price ?? 0),
      total,
      normalizedAvailable,
    ]
  );
  res.json({ success: true });
});
app.put('/api/books/:id', admin, async (req, res) => {
  const {
    title,
    author,
    publish_date,
    cover_url,
    cover_data,
    description,
    price,
    stock_total,
    stock_available,
  } = req.body;

  const total = Number(stock_total ?? 0);
  const available = Number(
    stock_available !== undefined ? stock_available : stock_total ?? 0
  );
  const normalizedAvailable = Math.min(Math.max(available, 0), Math.max(total, 0));
  const status = deriveBookStatus(total, normalizedAvailable);

  await pool.query(
    `UPDATE books
       SET title=?,
           author=?,
           publish_date=?,
           status=?,
           cover_url=?,
           description=?,
           price=?,
           stock_total=?,
           stock_available=?
     WHERE id=?`,
    [
      title,
      author,
      publish_date,
      status,
      cover_data || cover_url || DEFAULT_COVER,
      description || null,
      Number(price ?? 0),
      total,
      normalizedAvailable,
      req.params.id,
    ]
  );
  res.json({ success: true });
});
app.delete('/api/books/:id', admin, async (req, res) => {
  await pool.query('DELETE FROM books WHERE id=?', [req.params.id]);
  res.json({ success: true });
});

// 用户
app.get('/api/users', admin, async (_req, res) => {
  const [rows] = await pool.query('SELECT id, username, role, avatar_url, nickname, email FROM users');
  res.json(rows.map(formatUser));
});
app.post('/api/users', admin, async (req, res) => {
  const { username, role, avatar, email } = req.body;
  const hash = await bcrypt.hash('123456', 10);
  await pool.query(
    'INSERT INTO users (username, password, role, avatar_url, nickname, email) VALUES (?, ?, ?, ?, ?, ?)',
    [
      username,
      hash,
      role || 'user',
      avatar || generateDefaultAvatar(username),
      username,
      email || null,
    ]
  );
  res.json({ success: true });
});
app.put('/api/users/:id', admin, async (req, res) => {
  const { username, role, avatar, email } = req.body;
  const avatarUrl = avatar || generateDefaultAvatar(username);
  await pool.query(
    'UPDATE users SET username=?, role=?, avatar_url=?, nickname=?, email=? WHERE id=?',
    [username, role, avatarUrl, username, email || null, req.params.id]
  );
  res.json({ success: true });
});
app.delete('/api/users/:id', admin, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id=?', [req.params.id]);
  res.json({ success: true });
});

// 借阅
app.get('/api/borrow', admin, async (_req, res) => {
  try {
    // 检查列是否存在
    const [bookCols] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'books' AND COLUMN_NAME = 'cover_url'`
    );
    const [userCols] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'`
    );
    
    const coverField = bookCols.length > 0 ? 'books.cover_url AS cover_url' : 'NULL AS cover_url';
    const avatarField = userCols.find(c => c.COLUMN_NAME === 'avatar_url')
      ? 'users.avatar_url AS avatar'
      : 'NULL AS avatar';
    const emailField = userCols.find(c => c.COLUMN_NAME === 'email')
      ? 'users.email AS email'
      : 'NULL AS email';
    
    const [rows] = await pool.query(`
      SELECT b.id,
             books.title        AS book_title,
             ${coverField},
             users.username,
             ${avatarField},
             ${emailField},
             DATE_FORMAT(b.borrow_date, '%Y-%m-%d %H:%i:%s') AS borrow_date,
             CASE 
               WHEN b.return_date IS NOT NULL THEN DATE_FORMAT(b.return_date, '%Y-%m-%d %H:%i:%s')
               ELSE NULL
             END AS return_date,
             b.status
      FROM borrow b
      JOIN books ON b.book_id = books.id
      JOIN users ON b.user_id = users.id
      ORDER BY b.borrow_date DESC
    `);
    res.json(rows || []);
  } catch (e) {
    console.error('[/api/borrow] 错误:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/borrow', admin, async (req, res) => {
  try {
    const { book_id, user_id } = req.body;
    await borrowBook({ bookId: book_id, userId: user_id });
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.put('/api/borrow/:id/return', admin, async (req, res) => {
  try {
    await returnBook({ borrowId: req.params.id });
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.delete('/api/borrow/:id', admin, async (req, res) => {
  try {
    await pool.query('DELETE FROM borrow WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get('/api/my/borrow', async (req, res) => {
  try {
    // 检查 cover_url 列是否存在
    const [cols] = await pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'books' AND COLUMN_NAME = 'cover_url'`
    );
    const hasCoverUrl = cols.length > 0;
    
    const coverField = hasCoverUrl ? 'books.cover_url AS cover_url' : 'NULL AS cover_url';
    
    const [rows] = await pool.query(
      `
      SELECT b.id,
             books.title      AS book_title,
             ${coverField},
             DATE_FORMAT(b.borrow_date, '%Y-%m-%d %H:%i:%s') AS borrow_date,
             CASE 
               WHEN b.return_date IS NOT NULL THEN DATE_FORMAT(b.return_date, '%Y-%m-%d %H:%i:%s')
               ELSE NULL
             END AS return_date,
             b.status
        FROM borrow b
        JOIN books ON b.book_id = books.id
       WHERE b.user_id = ?
       ORDER BY b.borrow_date DESC
    `,
      [req.user.id]
    );
    res.json(rows || []);
  } catch (e) {
    console.error('[/api/my/borrow] 错误:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/my/borrow', async (req, res) => {
  try {
    const { book_id } = req.body;
    if (!book_id) {
      return res.status(400).json({ error: '缺少 book_id 参数' });
    }
    await borrowBook({ bookId: book_id, userId: req.user.id });
    res.json({ success: true });
  } catch (e) {
    console.error('[/api/my/borrow POST] 错误:', e);
    res.status(400).json({ error: e.message || '借阅失败' });
  }
});

app.put('/api/my/borrow/:id/return', async (req, res) => {
  try {
    await returnBook({ borrowId: req.params.id });
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// 仪表盘
app.get('/api/stats', async (_req, res) => {
  console.log("chuafa")
  try {
    const [rows] = await pool.query(`
      SELECT
        (SELECT COALESCE(SUM(COALESCE(stock_total, 0)), 0) FROM books) AS books,
        (SELECT COUNT(*) FROM users) AS users,
        (SELECT COUNT(*) FROM borrow WHERE status = 'borrowed') AS borrowed,
        (SELECT COALESCE(SUM(COALESCE(stock_available, 0)), 0) FROM books) AS inLibrary
    `);
    const result = rows[0] || { books: 0, users: 0, borrowed: 0, inLibrary: 0 };
    // 确保所有值都是数字类型
    result.books = Number(result.books) || 0;
    result.users = Number(result.users) || 0;
    result.borrowed = Number(result.borrowed) || 0;
    result.inLibrary = Number(result.inLibrary) || 0;
    console.log('[/api/stats] 返回数据:', result);
    return res.json(result);
  } catch (e) {
    console.error('[/api/stats] 错误:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/my/stats', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `
      SELECT
        (SELECT COUNT(*) FROM borrow WHERE user_id = ? AND status = 'borrowed') AS borrowing,
        (SELECT COUNT(*) FROM borrow WHERE user_id = ? AND status = 'returned') AS returned,
        (SELECT COUNT(*) FROM books) AS totalBooks
    `,
      [req.user.id, req.user.id]
    );
    res.json(rows[0] || { borrowing: 0, returned: 0, totalBooks: 0 });
  } catch (e) {
    console.error('[/api/my/stats] 错误:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/borrow-trend', async (_req, res) => {
  try {
    const days = [];
    const today = new Date();
    for (let i = 6; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(today.getDate() - i);
      const key = d.toISOString().slice(0, 10);
      days.push(key);
    }

    const [rows] = await pool.query(
      `
      SELECT DATE(borrow_date) AS day, COUNT(*) AS count
        FROM borrow
       WHERE borrow_date >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
       GROUP BY day
      `
    );
    const map = new Map(
      rows.map(r => {
        const key = new Date(r.day).toISOString().slice(0, 10);
        return [key, Number(r.count)];
      })
    );
    const result = days.map(day => ({ date: day, count: map.get(day) || 0 }));
    res.json(result);
  } catch (e) {
    console.error('[/api/borrow-trend] 错误:', e);
    res.status(500).json({ error: e.message });
  }
});

// ⑦ 启动
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Server ready at http://localhost:${PORT}`));
