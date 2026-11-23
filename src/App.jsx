import { useEffect, useMemo, useRef, useState } from 'react';
import {
  checkStrength,
  generatePassword,
  checkBreach,
  encryptNote,
  decryptNote,
} from './passwordLogic';
import './style.css';

export default function App() {
  const [theme, setTheme] = useState('dark');
  const [tab, setTab] = useState('check');

  const [pw, setPw] = useState('');
  const [show, setShow] = useState(false);
  const [copied, setCopied] = useState(false);
  const [length, setLength] = useState(16);
  const [upper, setUpper] = useState(true);
  const [lower, setLower] = useState(true);
  const [number, setNumber] = useState(true);
  const [symbol, setSymbol] = useState(true);
  const [loading, setLoading] = useState(false);
  const [breach, setBreach] = useState(null);
  const [err, setErr] = useState('');

  // 동일 비밀번호 중복 조회 방지용 캐시(현재 세션 메모리에서만 유지)
  const lastCheckedRef = useRef({ pw: '', result: null });

  const [vaultKey, setVaultKey] = useState('');
  const [noteInput, setNoteInput] = useState('');
  const [cipherText, setCipherText] = useState('');
  const [decryptedText, setDecryptedText] = useState('');
  const [vaultStatus, setVaultStatus] = useState('');

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  const strength = useMemo(() => checkStrength(pw), [pw]);

  const handleGenerate = () => {
    setPw(generatePassword({ length, upper, lower, number, symbol }));
    setBreach(null);
    setErr('');
    setCopied(false);
    lastCheckedRef.current = { pw: '', result: null };
  };

  const handleCopy = async () => {
    if (!pw) return;
    await navigator.clipboard.writeText(pw);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const handleCheck = async () => {
    if (loading) return;
    if (!pw) return setErr('비밀번호를 입력하세요.');

    if (lastCheckedRef.current.pw === pw && lastCheckedRef.current.result) {
      setErr('');
      setBreach(lastCheckedRef.current.result);
      return;
    }

    setLoading(true);
    setErr('');
    setBreach(null);
    try {
      const res = await checkBreach(pw);
      lastCheckedRef.current = { pw, result: res };
      setBreach(res);
    } catch (e) {
      setErr(e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleEncrypt = async () => {
    setVaultStatus('');
    setDecryptedText('');
    if (!vaultKey || !noteInput) {
      return setVaultStatus('암호화 키와 메모 내용을 모두 입력하세요.');
    }
    try {
      const enc = await encryptNote(vaultKey, noteInput);
      setCipherText(enc);
      setVaultStatus('AES-GCM 암호화 완료 (현재 세션 메모리에서만 유지됩니다).');
    } catch {
      setVaultStatus('암호화 중 오류가 발생했습니다.');
    }
  };

  const handleDecrypt = async () => {
    setVaultStatus('');
    if (!vaultKey || !cipherText) {
      return setVaultStatus('복호화할 키와 암호문이 필요합니다.');
    }
    try {
      const plain = await decryptNote(vaultKey, cipherText);
      setDecryptedText(plain);
      setVaultStatus('복호화 성공');
    } catch {
      setDecryptedText('');
      setVaultStatus('복호화 실패: 키가 다르거나 데이터가 손상되었습니다.');
    }
  };

  const handleClearVault = () => {
    setVaultKey('');
    setNoteInput('');
    setCipherText('');
    setDecryptedText('');
    setVaultStatus('메모와 키를 초기화했습니다.');
  };

  return (
    <main className="wrap">
      <header className="top">
        <div>
          <span className="tag">26-w12-password</span>
          <h1>비밀번호 보안 도구</h1>
        </div>
        <button
          type="button"
          className="ghost"
          onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
        >
          {theme === 'dark' ? '☀️ 밝은 모드' : '🌙 다크 모드'}
        </button>
      </header>

      <nav className="tabs">
        <button
          type="button"
          className={tab === 'check' ? 'tab active' : 'tab'}
          onClick={() => setTab('check')}
        >
          강도·생성·유출 확인
        </button>
        <button
          type="button"
          className={tab === 'vault' ? 'tab active' : 'tab'}
          onClick={() => setTab('vault')}
        >
          AES 암호화 메모
        </button>
      </nav>

      {tab === 'check' ? (
        <>
          <section className="box">
            <h2>비밀번호 강도 &amp; 유출 확인</h2>
            <div className="row">
              <input
                type={show ? 'text' : 'password'}
                value={pw}
                onChange={(e) => {
                  setPw(e.target.value);
                  setBreach(null);
                  setErr('');
                }}
                placeholder="비밀번호 입력"
                autoComplete="off"
              />
              <button type="button" className="ghost" onClick={() => setShow((v) => !v)}>
                {show ? '숨김' : '보기'}
              </button>
              <button type="button" className="ghost" onClick={handleCopy} disabled={!pw}>
                {copied ? '복사됨' : '복사'}
              </button>
              <button type="button" onClick={handleCheck} disabled={loading}>
                {loading ? '확인 중...' : '유출 확인'}
              </button>
            </div>

            <div className="meter">
              <div className="meter-head">
                <span>
                  강도: <b>{strength.label}</b>
                </span>
                <span>{strength.score}점</span>
              </div>
              <div className="bar">
                <i className={strength.level} style={{ width: `${strength.score}%` }} />
              </div>
            </div>

            {strength.checks.length > 0 && (
              <div className="chips">
                {strength.checks.map((c) => (
                  <span key={c.label} className={c.ok ? 'chip ok' : 'chip'}>
                    {c.ok ? '✓' : '·'} {c.label}
                  </span>
                ))}
                {strength.weakPattern && <span className="chip warn">! 흔한/반복 패턴 감지</span>}
              </div>
            )}

            {err && <p className="msg err">{err}</p>}

            {breach && (
              <div className={`msg ${breach.breached ? 'bad' : 'ok'}`}>
                <div>
                  {breach.breached
                    ? `유출됨 (${breach.count.toLocaleString()}회 확인)`
                    : '유출 이력 없음'}
                </div>
                <div className="hash-split">
                  <span>전송(앞 5자): <code>{breach.prefix}</code></span>
                  <span>로컬 비교(뒤 35자): <code>{breach.suffix}</code></span>
                </div>
                <small>{breach.url}</small>
              </div>
            )}
          </section>

          <section className="box">
            <h2>안전한 비밀번호 생성기</h2>
            <label className="full">
              <span>
                길이: <b>{length}자</b>
              </span>
              <input
                type="range"
                min="8"
                max="32"
                value={length}
                onChange={(e) => setLength(Number(e.target.value))}
              />
            </label>
            <div className="opts">
              <label>
                <input type="checkbox" checked={upper} onChange={(e) => setUpper(e.target.checked)} />
                대문자
              </label>
              <label>
                <input type="checkbox" checked={lower} onChange={(e) => setLower(e.target.checked)} />
                소문자
              </label>
              <label>
                <input type="checkbox" checked={number} onChange={(e) => setNumber(e.target.checked)} />
                숫자
              </label>
              <label>
                <input type="checkbox" checked={symbol} onChange={(e) => setSymbol(e.target.checked)} />
                특수문자
              </label>
            </div>
            <button type="button" onClick={handleGenerate}>
              새 비밀번호 생성
            </button>
          </section>
        </>
      ) : (
        <section className="box">
          <h2>AES-GCM 암호화 메모 (PBKDF2)</h2>
          <p className="desc">
            입력한 키로 브라우저에서 직접 암호화·복호화하며, 서버나 스토리지에 저장하지 않습니다.
          </p>

          <label className="full">
            <span>마스터 키 / 비밀번호</span>
            <input
              type="password"
              value={vaultKey}
              onChange={(e) => setVaultKey(e.target.value)}
              placeholder="암호화·복호화에 쓸 키 입력"
              autoComplete="off"
            />
          </label>

          <label className="full">
            <span>원문 메모</span>
            <textarea
              rows="3"
              value={noteInput}
              onChange={(e) => setNoteInput(e.target.value)}
              placeholder="암호화할 메모 입력"
            />
          </label>

          <div className="row">
            <button type="button" onClick={handleEncrypt}>
              암호화
            </button>
            <button type="button" className="ghost" onClick={handleDecrypt}>
              복호화
            </button>
            <button type="button" className="ghost" onClick={handleClearVault}>
              지우기 / 잠그기
            </button>
          </div>

          <label className="full top-gap">
            <span>암호문 (JSON)</span>
            <textarea
              rows="3"
              value={cipherText}
              onChange={(e) => setCipherText(e.target.value)}
              placeholder="암호화 결과가 여기에 표시됩니다"
            />
          </label>

          {decryptedText && (
            <div className="msg ok">
              <b>복호화된 메모:</b> {decryptedText}
            </div>
          )}

          {vaultStatus && <p className="msg info">{vaultStatus}</p>}
        </section>
      )}
    </main>
  );
}