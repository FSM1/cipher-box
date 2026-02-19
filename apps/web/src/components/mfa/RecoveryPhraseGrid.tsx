/**
 * RecoveryPhraseGrid displays a 24-word mnemonic recovery phrase
 * in a 4-column numbered grid with terminal aesthetic.
 *
 * Words are numbered 1-24 and displayed in monospace font.
 * The grid is read-only but allows copy-paste for user convenience.
 */

type RecoveryPhraseGridProps = {
  words: string[];
};

export function RecoveryPhraseGrid({ words }: RecoveryPhraseGridProps) {
  return (
    <div className="recovery-phrase-grid" aria-label="Recovery phrase">
      {words.map((word, index) => (
        <div key={index} className="recovery-phrase-cell">
          <span className="recovery-phrase-number">{String(index + 1).padStart(2, '0')}</span>
          <span className="recovery-phrase-word">{word}</span>
        </div>
      ))}
    </div>
  );
}
