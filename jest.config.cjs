module.exports = {
  resolver: "jest-ts-webcompat-resolver",
  transform: {
    ".(ts|tsx)": "ts-jest"
  },
  testEnvironment: "node",
  testRegex: "(/__tests__/.*|\\.(test|spec))\\.(ts|tsx|js)$",
  moduleFileExtensions: [
    "ts",
    "tsx",
    "js"
  ],
  collectCoverage: true,
  coverageDirectory: "coverage",
  coverageProvider: "v8",
  coveragePathIgnorePatterns: [
    "/node_modules/",
    "/test/",
    "/src/idb"
  ],
  coverageThreshold: {
    global: {
      branches: 90,
      functions: 95,
      lines: 95,
      statements: 95
    }
  },
  collectCoverageFrom: [
    "src/**/*.{js,ts}"
  ],
  globals: {
    globalThis: {
      crypto: {
        subtle: {}
      }
    },
    localForage: {}
  },
  restoreMocks: true
}
