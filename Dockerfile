# Dockerfile

# 1. Start from an official, lightweight Node.js image
# 'alpine' is a minimal version of Linux, making our image smaller
FROM node:18-alpine

# 2. Set the working directory inside the container
# All subsequent commands will run from this path
WORKDIR /app

# 3. Copy package.json and package-lock.json to the container
# This is done first to leverage Docker's caching. If these files don't change,
# Docker won't re-run the npm install step, speeding up future builds.
COPY package*.json ./

# 4. Install the application's dependencies
RUN npm install

# 5. Copy the rest of your application's code into the container
COPY . .

# 6. Expose the port that the application runs on
# This tells Docker that the container will listen on port 3000
EXPOSE 3000

# 7. Define the command to start the application
# This is what runs when the container starts
CMD ["node", "index.js"]
