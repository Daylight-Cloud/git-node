// middleware/admin.js
const { ROLE } = require('../constants/role');

/**
 * 管理员权限守卫
 * 必须在 auth 之后挂载
 */
function admin(req, res, next) {
  if (req.user.role !== ROLE.ADMIN) {
    return res.status(403).json({ error: '需要管理员权限' });
  }
  next();
}

module.exports = admin;