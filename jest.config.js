module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  verbose: true,
  collectCoverage: true,
  testPathIgnorePatterns: ['dist/', 'node_modules/'],
}
