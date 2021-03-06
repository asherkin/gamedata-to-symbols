Start
  = __ keyvalues:KeyValue* {
      return keyvalues;
    }

KeyValue
  = key:Key __ value:(Value / Section) __ {
      return {key: key, value: value};
    }

Key "key"
  = QuotedString

Value "value"
  = QuotedString

Section "section"
  = "{" __ keyvalues:KeyValue* "}" {
      return keyvalues;
    }

QuotedString "string"
  = '"' chars:DoubleStringCharacter* '"' {
      return chars.join("");
    }

DoubleStringCharacter
  = !('"' / "\\") SourceCharacter { return text(); }
  / "\\" sequence:EscapeSequence { return sequence; }

EscapeSequence
  = CharacterEscapeSequence
//  / HexEscapeSequence

CharacterEscapeSequence
  = SingleEscapeCharacter
  / char:NonEscapeCharacter { return "\\" + char; }

SingleEscapeCharacter
  = '"'
  / "\\"
  / "n"  { return "\n"; }
  / "r"  { return "\r"; }
  / "t"  { return "\t"; }

/*
HexDigit
  = [0-9a-f]i

HexEscapeSequence
  = "x" digits:$(HexDigit HexDigit) {
      return String.fromCharCode(parseInt(digits, 16));
    }
*/

NonEscapeCharacter
  = !EscapeCharacter SourceCharacter { return text(); }

EscapeCharacter
  = SingleEscapeCharacter
//  / "x"

SourceCharacter
  = .

WhiteSpace "whitespace"
  = "\t"
  / "\v"
  / "\f"
  / " "

LineTerminator
  = [\n\r]

LineTerminatorSequence "end of line"
  = "\n"
  / "\r\n"
  / "\r"

Comment "comment"
  = MultiLineComment
  / SingleLineComment

MultiLineComment
  = "/*" (!"*/" SourceCharacter)* "*/"

MultiLineCommentNoLineTerminator
  = "/*" (!("*/" / LineTerminator) SourceCharacter)* "*/"

SingleLineComment
  = "//" (!LineTerminator SourceCharacter)*

__
  = (WhiteSpace / LineTerminatorSequence / Comment)*
