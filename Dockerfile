FROM node:22-alpine

# 1. 指定工作目录
WORKDIR /app

# 2. 先复制依赖描述文件 → 充分利用层缓存
COPY package*.json ./

# 3. 安装生产依赖（npm ci 比 install 更快、更干净）
RUN npm ci --only=production --silent && \
    npm cache clean --force

# 4. 复制其余源码（已含 nuxt.config.js、static、.nuxt 等）
COPY . .

# 5. 如果源码里**没有**提前 generate/.nuxt，需要现场 build（不需要就注释掉）
# RUN npm run build

# 6. 暴露 Nuxt 默认端口
EXPOSE 3000

# 7. 启动生产服务
CMD ["npm", "run", "start"]