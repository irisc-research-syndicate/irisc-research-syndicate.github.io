require 'rouge'

module Rouge
  module Lexers
    class MyLang < RegexLexer
      title "Ghidra sleigh lexer"
      desc "A custom lexer for Ghidra Sleigh"
      tag 'sleigh'
      filenames '*.slaspec'

      # Define Registers and Variables

      state :root do
        rule %r/\b0x[0-9A-Fa-f]+\b/, Literal::Number::Hex
        rule %r/\b\d+\b/, Literal::Number

        rule %r/(inst_start|inst_next)/, Name::Builtin

        rule %r/#.*/, Comment::Single

        rule %r/(define|attach|macro|export|local|is|with|endian|goto|call|return|subtable)/, Keyword

        # Registers
        rule %r/\b(r[0-9]+|r[0-9]+l|r[0-9]+h|zero|zeroh|zerol)\b/, Name::Builtin

        # Identifiers (Variables, Labels)
        rule %r/\b[a-zA-Z_][a-zA-Z0-9_]*\b/, Name::Variable

        # Operators
        rule %r/[=+\-*\/<>!&|%^~]/, Operator

        # Punctuation
        rule %r/[{}();,\[\]:]/, Punctuation

        # Default text
        rule %r/\s+/, Text
      end
    end
  end
end