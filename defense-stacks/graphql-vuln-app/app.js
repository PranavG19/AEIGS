"use strict";

const express = require("express");
const { graphqlHTTP } = require("express-graphql");
const {
  GraphQLSchema,
  GraphQLObjectType,
  GraphQLString,
  GraphQLList,
  GraphQLBoolean,
  GraphQLNonNull,
} = require("graphql");
const Database = require("better-sqlite3");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = 4000;
const DISABLE_INTROSPECTION = process.env.DISABLE_INTROSPECTION === "1";

const db = new Database(":memory:");
db.exec(`
  CREATE TABLE users (id TEXT, name TEXT, email TEXT, ssn TEXT, role TEXT);
  INSERT INTO users VALUES ('1', 'Alice', 'alice@example.com', '123-45-6789', 'admin');
  INSERT INTO users VALUES ('2', 'Bob', 'bob@example.com', '987-65-4321', 'user');
  INSERT INTO users VALUES ('3', 'Charlie', 'charlie@example.com', '555-12-3456', 'user');
`);

const UserType = new GraphQLObjectType({
  name: "User",
  fields: {
    id: { type: GraphQLString },
    name: { type: GraphQLString },
    email: { type: GraphQLString },
    ssn: { type: GraphQLString },
    role: { type: GraphQLString },
  },
});

const SearchResultType = new GraphQLObjectType({
  name: "SearchResult",
  fields: {
    title: { type: GraphQLString },
    snippet: { type: GraphQLString },
  },
});

const FileContentType = new GraphQLObjectType({
  name: "FileContent",
  fields: {
    path: { type: GraphQLString },
    content: { type: GraphQLString },
  },
});

const AuthResultType = new GraphQLObjectType({
  name: "AuthResult",
  fields: {
    token: { type: GraphQLString },
    success: { type: GraphQLBoolean },
  },
});

const QueryType = new GraphQLObjectType({
  name: "Query",
  fields: {
    user: {
      type: UserType,
      args: { id: { type: new GraphQLNonNull(GraphQLString) } },
      resolve(_parent, args) {
        // VULN: SQL injection via string concatenation
        const sql = "SELECT * FROM users WHERE id = '" + args.id + "'";
        return db.prepare(sql).get();
      },
    },

    users: {
      type: new GraphQLList(UserType),
      args: { filter: { type: GraphQLString } },
      resolve(_parent, args) {
        if (!args.filter) {
          return db.prepare("SELECT * FROM users").all();
        }
        // VULN: SQL injection via string concatenation
        const sql =
          "SELECT * FROM users WHERE name LIKE '%" + args.filter + "%'";
        return db.prepare(sql).all();
      },
    },

    search: {
      type: new GraphQLList(SearchResultType),
      args: { query: { type: new GraphQLNonNull(GraphQLString) } },
      resolve(_parent, args) {
        // VULN: XSS via reflected user input in snippet (unescaped)
        return [
          {
            title: "Search results for: " + args.query,
            snippet:
              "Found matches containing <b>" + args.query + "</b> in records",
          },
        ];
      },
    },

    file: {
      type: FileContentType,
      args: { path: { type: new GraphQLNonNull(GraphQLString) } },
      resolve(_parent, args) {
        // VULN: path traversal — reads arbitrary files
        const filePath = path.join("/app/data", args.path);
        try {
          const content = fs.readFileSync(filePath, "utf-8");
          return { path: args.path, content };
        } catch (err) {
          return { path: args.path, content: "Error: " + err.message };
        }
      },
    },
  },
});

const MutationType = new GraphQLObjectType({
  name: "Mutation",
  fields: {
    login: {
      type: AuthResultType,
      args: {
        username: { type: new GraphQLNonNull(GraphQLString) },
        password: { type: new GraphQLNonNull(GraphQLString) },
      },
      resolve(_parent, args) {
        // VULN: broken authentication — hardcoded credentials, always returns token
        const token = crypto.randomBytes(16).toString("hex");
        if (args.username === "admin" && args.password === "admin") {
          return { token, success: true };
        }
        // Still returns a token even on failure (broken auth)
        return { token, success: true };
      },
    },

    updateProfile: {
      type: UserType,
      args: {
        userId: { type: new GraphQLNonNull(GraphQLString) },
        data: { type: new GraphQLNonNull(GraphQLString) },
      },
      resolve(_parent, args) {
        // VULN: IDOR — no authorization check, any user can update any profile
        const sql =
          "UPDATE users SET name = '" +
          args.data +
          "' WHERE id = '" +
          args.userId +
          "'";
        db.prepare(sql).run();
        const selectSql =
          "SELECT * FROM users WHERE id = '" + args.userId + "'";
        return db.prepare(selectSql).get();
      },
    },

    deleteUser: {
      type: GraphQLBoolean,
      args: { userId: { type: new GraphQLNonNull(GraphQLString) } },
      resolve(_parent, args) {
        // VULN: no authentication required — anyone can delete users
        const sql = "DELETE FROM users WHERE id = '" + args.userId + "'";
        const result = db.prepare(sql).run();
        return result.changes > 0;
      },
    },
  },
});

const schema = new GraphQLSchema({
  query: QueryType,
  mutation: MutationType,
});

function introspectionBlocker(req, res, next) {
  if (DISABLE_INTROSPECTION && req.body) {
    const body =
      typeof req.body === "string" ? req.body : JSON.stringify(req.body);
    if (body.includes("__schema") || body.includes("__type")) {
      res.status(400).json({ errors: [{ message: "Introspection disabled" }] });
      return;
    }
  }
  next();
}

const app = express();

app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use(
  "/graphql",
  introspectionBlocker,
  graphqlHTTP({
    schema,
    graphiql: !DISABLE_INTROSPECTION,
  })
);

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `GraphQL vuln app listening on http://localhost:${PORT}/graphql`
  );
  if (DISABLE_INTROSPECTION) {
    console.log("Introspection is DISABLED");
  }
});
