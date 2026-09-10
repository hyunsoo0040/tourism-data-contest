"use client";

/**
 * Port of upstream UI/메인페이지.html + 메인페이지.css + 메인페이지.js
 * (authorized provenance, see fixtures/upstream-ui/provenance.json).
 *
 * Presentation, copy, DOM structure, palette, and typography are preserved.
 * Upstream vanilla-JS behavior is replaced by equivalent React state:
 * - the recommendation-preview chooser (recommendations dataset + phone card)
 * - the mobile menu toggle
 * - the reveal-on-scroll observer
 * - reading the upstream-persisted travel preference (type + keywords) to
 *   preselect the preview type
 *
 * The upstream script never executes; nothing here scores or recommends.
 * The type-test entry links route into the IT-DA journey (/start, /quiz,
 * /photo) which is served by the local backend as sole authority.
 */
import { useEffect, useMemo, useRef, useState } from "react";

const UPSTREAM_STORAGE_KEY = "itdaTravelPreference";
const PREVIEW_TYPES = ["history", "rest", "image"] as const;

type UpstreamPreference = {
  type?: string;
  keywords?: string[];
};

function readUpstreamPreference(): UpstreamPreference | null {
  try {
    return JSON.parse(window.localStorage.getItem(UPSTREAM_STORAGE_KEY) || "null") as
      | UpstreamPreference
      | null;
  } catch {
    return null;
  }
}

type RecommendationBranch = {
  title: string;
  phoneType: string;
  phoneDesc: string;
  match: number;
  text: string;
  places: Array<{ tag: string; title: string; desc: string; color: string }>;
};

/** Verbatim upstream preview dataset (copy provenance; not scoring). */
const RECOMMENDATIONS: Record<string, RecommendationBranch> = {
  rest: {
    title: "휴식·몰입형 추천 결과",
    phoneType: "당신은<br>휴식·몰입형 여행자",
    phoneDesc: "조용한 산책, 자유로운 공간, 오래 머무는 감정을 선호해요.",
    match: 84,
    text: "기대와 장소 분위기가 높은 수준으로 일치합니다.",
    places: [
      {
        tag: "휴식·몰입 84%",
        title: "보문호반길",
        desc: "보문호를 따라 천천히 걷거나 머물며 물가 풍경을 즐길 수 있는 경주의 산책 코스입니다.",
        color: "linear-gradient(135deg,#80ed99,#57cc99,#22577a)",
      },
      {
        tag: "감정 몰입 78%",
        title: "동궁과 월지",
        desc: "복원된 신라 궁궐과 연못 풍경을 둘러보며 낮과 밤의 서로 다른 분위기를 경험할 수 있습니다.",
        color: "linear-gradient(135deg,#cdb4db,#90dbf4,#8eecf5)",
      },
    ],
  },
  history: {
    title: "역사·전통형 추천 결과",
    phoneType: "당신은<br>역사·전통형 여행자",
    phoneDesc: "장소에 담긴 이야기와 문화적 맥락을 깊게 경험하고 싶어해요.",
    match: 89,
    text: "스토리와 문화 자원이 기대와 잘 맞습니다.",
    places: [
      {
        tag: "역사·전통 89%",
        title: "불국사",
        desc: "신라 불교문화와 석조 건축의 흐름을 한자리에서 살펴볼 수 있는 경주의 대표 문화유산입니다.",
        color: "linear-gradient(135deg,#f4a261,#e76f51,#7f5539)",
      },
      {
        tag: "스토리 적합 81%",
        title: "경주 양동마을",
        desc: "전통 가옥과 골목이 이어지는 마을을 걸으며 조선시대 생활문화와 건축을 살펴볼 수 있습니다.",
        color: "linear-gradient(135deg,#e9c46a,#bc6c25,#606c38)",
      },
    ],
  },
  image: {
    title: "감성·이미지형 추천 결과",
    phoneType: "당신은<br>감성·이미지형 여행자",
    phoneDesc: "사진으로 남기고 싶은 분위기와 시각적 인상을 중요하게 생각해요.",
    match: 86,
    text: "사진 분위기와 시각 키워드가 기대와 잘 맞습니다.",
    places: [
      {
        tag: "감성·이미지 86%",
        title: "황리단길",
        desc: "한옥과 상점이 어우러진 거리에서 경주의 현재적인 분위기와 다양한 거리 풍경을 만날 수 있습니다.",
        color: "linear-gradient(135deg,#ffafcc,#bde0fe,#a2d2ff)",
      },
      {
        tag: "포토 스팟 79%",
        title: "대릉원 일원",
        desc: "큰 고분과 산책로가 이어져 계절과 시간대에 따라 달라지는 경주의 풍경을 기록하기 좋습니다.",
        color: "linear-gradient(135deg,#ffb703,#fb8500,#219ebc)",
      },
    ],
  },
};

function PhoneTypeCopy({ html }: { html: string }) {
  // Upstream stores the two-line phone headline with an explicit <br>.
  return <b id="phoneType" dangerouslySetInnerHTML={{ __html: html }} />;
}

export function UpstreamMainPage() {
  const [openMenu, setOpenMenu] = useState(false);
  const [selectedType, setSelectedType] = useState<string>("rest");
  const rootRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const saved = readUpstreamPreference();
    if (saved?.type && saved.type in RECOMMENDATIONS) {
      setSelectedType(saved.type);
    }
  }, []);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setSelectedType((current) => {
        const currentIndex = PREVIEW_TYPES.indexOf(current as (typeof PREVIEW_TYPES)[number]);
        return PREVIEW_TYPES[(Math.max(0, currentIndex) + 1) % PREVIEW_TYPES.length]!;
      });
    }, 3_000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    const root = rootRef.current;
    if (root === null) return;
    const targets = root.querySelectorAll<HTMLElement>(".reveal");
    if (typeof IntersectionObserver === "undefined") {
      targets.forEach((target) => target.classList.add("visible"));
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            entry.target.classList.add("visible");
            observer.unobserve(entry.target);
          }
        }
      },
      { threshold: 0.12 },
    );
    targets.forEach((target) => observer.observe(target));
    return () => observer.disconnect();
  }, []);

  const data = useMemo(() => RECOMMENDATIONS[selectedType] ?? RECOMMENDATIONS.rest!, [selectedType]);

  return (
    <div className="up-root">
      <div className="up-main" ref={rootRef as React.RefObject<HTMLDivElement>}>
        <header className="site-header">
          <div className="wrap nav">
            <a href="/" className="logo" aria-label="IT-DA 메인으로 이동">
              <span className="logo-mark">잇</span> IT-DA
            </a>
            <button
              className="menu-toggle"
              type="button"
              aria-label={openMenu ? "메뉴 닫기" : "메뉴 열기"}
              aria-expanded={openMenu}
              onClick={() => setOpenMenu((open) => !open)}
            >
              <span></span>
              <span></span>
              <span></span>
            </button>
            <nav className={openMenu ? "nav-menu open" : "nav-menu"} aria-label="주요 메뉴">
              <a href="#type">여행 유형</a>
              <a href="#flow">서비스 흐름</a>
              <a href="#photo">사진 분위기 입력</a>
              <a href="#demo">추천 예시</a>
            </nav>
            <a href="/start" className="nav-cta">시작하기</a>
          </div>
        </header>

        <main>
          <section className="hero reveal visible">
            <div className="wrap hero-grid">
              <div>
                <div className="badge"><span></span> 관광데이터 기반 개인 맞춤 여행 큐레이션</div>
                <h1>
                  <span className="hero-title-line">가장 나다운 여행과</span>
                  <span className="hero-title-line">
                    <span className="gradient-text">진짜 맞는 장소</span>를 잇다
                  </span>
                </h1>
                <p>
                  당신은 어떤 여행에서 진짜다움을 느끼나요?<br />
                  테스트와 사진을 통해 추구하는 여행 경험을 알아보세요.<br />
                  전국에서 찾거나 원하는 지역을 골라, 내 취향에 가까운 여행지를 만나보세요.
                </p>
                <div className="hero-actions">
                  <a className="btn primary" href="/start">여행 취향 찾기</a>
                </div>
              </div>
              <div className="phone-card" aria-label="IT-DA 모바일 추천 화면 미리보기">
                <div className="blob"></div>
                <div className="phone">
                  <div className="screen">
                    <div className="screen-top"><span>IT-DA</span><span id="phoneMatch">{data.match}% match</span></div>
                    <div className="mini-hero">
                      <PhoneTypeCopy html={data.phoneType} />
                      <p id="phoneDesc">{data.phoneDesc}</p>
                    </div>
                    <div className="type-card">
                      <div className="type-icon">古</div>
                      <div>
                        <strong>역사·전통형</strong>
                        <span>문화, 유적, 자연 보존</span>
                      </div>
                    </div>
                    <div className="type-card">
                      <div className="type-icon">景</div>
                      <div>
                        <strong>감성·이미지형</strong>
                        <span>SNS, 분위기, 포토 스팟</span>
                      </div>
                    </div>
                    <div className="type-card">
                      <div className="type-icon">休</div>
                      <div>
                        <strong>휴식·몰입형</strong>
                        <span>산책, 조용함, 감정적 만족</span>
                      </div>
                    </div>
                    <div className="match">
                      <strong>추천 장소 적합도</strong>
                      <div className="bar"><i id="matchBar" style={{ width: `${data.match}%` }}></i></div>
                      <p id="matchText">{data.text}</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          <section id="type" className="reveal">
            <div className="wrap">
              <div className="section-head">
                <div>
                  <div className="eyebrow">Experience Type</div>
                  <h2>같은 여행도,<br />끌리는 이유는 다릅니다</h2>
                </div>
                <p></p>
              </div>
              <div className="type-visual" aria-label="어떤 사람은 장소에 담긴 이야기, 분위기와 이미지, 조용히 머무는 시간에 끌립니다">
                <strong className="type-visual__word type-visual__word--start">어떤 사람은</strong>
                <div className="type-visual__reasons">
                  <span>장소에 담긴 이야기에</span>
                  <span>분위기와 이미지에</span>
                  <span>또는 조용히 머무는 시간에</span>
                </div>
                <strong className="type-visual__word type-visual__word--end">끌립니다.</strong>
              </div>
              <p className="type-summary">IT-DA는 이러한 차이를 세 가지 여행 경험 유형으로 나누어 살펴봅니다.</p>
              <div className="cards">
                <article className="card"><div className="icon orange">古</div><h3>역사·전통형</h3><p>오랜 시간 보존되어 온 문화유산과 전통 공간이 지닌 역사적 가치와 고유한 의미를 중요하게 여기는 여행자를 위한 유형입니다.</p></article>
                <article className="card"><div className="icon blue">景</div><h3>감성·이미지형</h3><p>장소가 가진 분위기와 이미지, 미디어와 콘텐츠를 통해 형성된 의미를 중요하게 여기는 여행자를 위한 유형입니다.</p></article>
                <article className="card"><div className="icon green">休</div><h3>휴식·몰입형</h3><p>일상에서 벗어나 온전히 자신만의 시간을 보내며 휴식과 몰입의 경험을 중요하게 여기는 여행자를 위한 유형입니다.</p></article>
              </div>
            </div>
          </section>

          <section id="flow" className="reveal">
            <div className="wrap">
              <div className="section-head">
                <div>
                  <div className="eyebrow">Service Flow</div>
                  <h2>사용자 기대와 관광 데이터를<br />하나의 추천 흐름으로 연결합니다</h2>
                </div>
              </div>
              <div className="flow">
                <div className="step"><div className="num">01</div><strong>취향 입력</strong><p>테스트 또는 사진 업로드로 원하는 여행 분위기를 표현합니다.</p></div>
                <div className="step"><div className="num">02</div><strong>데이터 수집</strong><p>관광지 설명, 위치, 사진, 오디오 가이드 정보를 불러옵니다.</p></div>
                <div className="step"><div className="num">03</div><strong>분위기 분석</strong><p>사진은 경험 유형 판정이 아닌 감각적 분위기 신호로만 활용합니다.</p></div>
                <div className="step"><div className="num">04</div><strong>추천 제공</strong><p>유사한 분위기의 관광지와 추천 이유를 함께 안내합니다.</p></div>
              </div>
            </div>
          </section>

          <section id="photo" className="reveal">
            <div className="wrap photo-feature">
              <div>
                <div className="eyebrow">find your type</div>
                <h2>간단한 테스트로<br />나의 취향을 발견하세요</h2>
                <p>
                  테스트는 사용자의 경험 유형을 단정하는 기준이 아닙니다. 여행 중에 마주할 수 있는 우연들로
                  사용자가 감각적으로 끌리는 여행 장면을 더 쉽게 표현하도록 돕는 보조 입력입니다.
                </p>
              </div>
              <a className="photo-link" href="/start">
                <span>선택적 사진 입력</span>
                <strong>취향 테스트 후 사진 분위기 더하기</strong>
                <em>결과 화면에서 원하는 분위기 사진 추가 입력 가능</em>
              </a>
            </div>
          </section>

          <section id="demo" className="reveal">
            <div className="wrap demo">
              <div className="quiz">
                <div className="eyebrow">type test</div>
                <h3>간단 선택으로 추천 미리보기</h3>
                <button
                  className={selectedType === "history" ? "choice active" : "choice"}
                  type="button"
                  data-type="history"
                  onClick={() => setSelectedType("history")}
                >
                  <i></i><span>오래된 이야기와 전통이 살아있는 공간</span>
                </button>
                <button
                  className={selectedType === "rest" ? "choice active" : "choice"}
                  type="button"
                  data-type="rest"
                  onClick={() => setSelectedType("rest")}
                >
                  <i></i><span>조용히 걷고 머물 수 있는 차분한 분위기</span>
                </button>
                <button
                  className={selectedType === "image" ? "choice active" : "choice"}
                  type="button"
                  data-type="image"
                  onClick={() => setSelectedType("image")}
                >
                  <i></i><span>사진으로 남기고 싶은 감성적인 장소</span>
                </button>
                <a className="test-link" href="/quiz">12문항 취향 테스트로 자세히 보기</a>
              </div>
              <div className="result">
                <div className="eyebrow">Recommendation Preview</div>
                <h2 id="resultTitle">{data.title}</h2>
                <div id="recommendations">
                  {data.places.map((place) => (
                    <div className="place" key={place.title}>
                      <div className="photo" style={{ background: place.color }}></div>
                      <div>
                        <span className="tag">{place.tag}</span>
                        <h4>{place.title}</h4>
                        <p>{place.desc}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>

          <section id="data" className="reveal">
            <div className="wrap">
              <div className="section-head">
                <div>
                  <div className="eyebrow">Tour Data</div>
                  <h2>공공 관광데이터를<br />추천 기능으로 전환합니다</h2>
                </div>
              </div>
              <div className="data-list">
                <div className="data-item"><b>국문 관광정보</b><span>관광지 기본 DB와 장소 설명 분석</span></div>
                <div className="data-item"><b>Odii 오디오 가이드</b><span>역사·문화 스토리와 전통성 분석</span></div>
                <div className="data-item"><b>관광사진 자료</b><span>사진 분위기와 이미지 키워드 매칭</span></div>
                <div className="data-item"><b>연계 관광지 정보</b><span>추천 장소를 하루 코스로 확장</span></div>
              </div>
            </div>
          </section>
        </main>

        <nav className="mobile-tabs" aria-label="모바일 빠른 이동">
          <a href="#type">유형</a>
          <a href="#photo">사진</a>
          <a href="#demo">추천</a>
        </nav>

        <footer>
          <div className="wrap">© 2026 IT-DA. Tourism Data Curation Service.</div>
        </footer>
      </div>
    </div>
  );
}
