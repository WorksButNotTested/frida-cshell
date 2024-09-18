import globals from "globals";
import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";


export default [
  {files: ["**/*.{js,mjs,cjs,ts}"]},
  {languageOptions: { globals: globals.browser }},
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": [
          "error", // or "error"
          {
              "argsIgnorePattern": "^_",
              "varsIgnorePattern": "^_",
              "caughtErrorsIgnorePattern": "^_"
          }
      ]
    }
  }
];
