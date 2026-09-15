"use client";

/**
 * Port of upstream UI/메인페이지.html + 메인페이지.css + 메인페이지.js
 * (authorized provenance, see fixtures/upstream-ui/provenance.json).
 *
 * Presentation, copy, DOM structure, palette, and typography are preserved.
 * Upstream vanilla-JS behavior is replaced by equivalent React state:
 * - the recommendation-preview chooser (verified PUBLIC examples + official photographs)
 * - the mobile menu toggle
 * - the reveal-on-scroll observer
 * - reading the upstream-persisted travel preference (type + keywords) to
 *   preselect the preview type
 *
 * The upstream script never executes. Example scores are exported from the
 * verified PUBLIC release. The phone illustrates type-based matching;
 * the homepage does not create a personalized ranking.
 * The type-test entry links route into the IT-DA journey (/start, /quiz,
 * /profile) which is served by the local backend as sole authority.
 */
import { useEffect, useRef, useState } from "react";
import examples from "../../content/public-place-examples.json";
import "../styles/place-examples.css";
import "../styles/phone-preview.css";
import { PlacePhotos } from "../../features/authenticity/PlacePhotos";
import { placeMapUrl } from "../../features/authenticity/placeMetadata";

const MAIN_NAV_ITEMS = [
  { id: "type", label: "여행 유형" },
  { id: "flow", label: "서비스 흐름" },
  { id: "demo", label: "추천 예시" },
] as const;

const UPSTREAM_STORAGE_KEY = "itdaTravelPreference";

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

const RECOMMENDATIONS = {
  history: {
    title: "역사·전통을 만나는 장소",
    phoneType: "그곳만이 가진 고유한<br>모습을 직접 만나고 싶다면",
    phoneDesc: "관광 대상 자체가 지닌 원형과 역사적·문화적 가치를 경험해보세요.",
    axisLabel: "대상·원형형", places: examples.examples.history,
  },
  image: {
    title: "감성·이미지를 만나는 장소",
    phoneType: "익숙하게 그려온 그곳의<br>모습을 직접 만나고 싶다면",
    phoneDesc: "사람들의 인식과 이야기 속에서 형성된 장소의 모습을 경험해보세요.",
    axisLabel: "의미·이미지형", places: examples.examples.image,
  },
  rest: {
    title: "휴식·몰입을 만나는 장소",
    phoneType: "일상의 나에서 벗어나<br>자유롭게 여행하고 싶다면",
    phoneDesc: "평소의 역할과 틀에서 벗어나 자신만의 방식으로 경험해보세요.",
    axisLabel: "자기·몰입", places: examples.examples.rest,
  },
};

function PhoneTypeCopy({ html }: { html: string }) {
  // Upstream stores the two-line phone headline with an explicit <br>.
  return <b id="phoneType" dangerouslySetInnerHTML={{ __html: html }} />;
}

type RecommendationType = keyof typeof RECOMMENDATIONS;

const RECOMMENDATION_TYPES: RecommendationType[] = ["history", "image", "rest"];

const PHONE_TYPES = [
  { type: "history", icon: "原", label: "대상·원형형", description: "원형 · 고유성 · 역사성" },
  { type: "image", icon: "像", label: "의미·이미지형", description: "이미지 · 기대 · 인식" },
  { type: "rest", icon: "我", label: "자기·몰입형", description: "자유 · 자기표현 · 몰입" },
] as const;

function PhonePreview({ selectedType }: { selectedType: RecommendationType }) {
  const [phoneType, setPhoneType] = useState(selectedType);
  const [hovered, setHovered] = useState(false);
  const [focused, setFocused] = useState(false);
  const [inView, setInView] = useState(false);
  const [pageVisible, setPageVisible] = useState(true);
  const [reducedMotion, setReducedMotion] = useState(false);
  const phoneRef = useRef<HTMLDivElement>(null);
  const data = RECOMMENDATIONS[phoneType];

  useEffect(() => setPhoneType(selectedType), [selectedType]);

  useEffect(() => {
    const phone = phoneRef.current;
    if (phone === null) return;
    if (typeof IntersectionObserver === "undefined") {
      setInView(true);
      return;
    }
    const observer = new IntersectionObserver(
      ([entry]) => setInView(entry.isIntersecting), { threshold: 0.25 },
    );
    observer.observe(phone);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const updateVisibility = () => setPageVisible(!document.hidden);
    const preference = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    const updateMotion = () => setReducedMotion(preference?.matches ?? false);
    updateVisibility();
    updateMotion();
    document.addEventListener("visibilitychange", updateVisibility);
    preference?.addEventListener("change", updateMotion);
    return () => {
      document.removeEventListener("visibilitychange", updateVisibility);
      preference?.removeEventListener("change", updateMotion);
    };
  }, []);

  useEffect(() => {
    if (hovered || focused || !inView || !pageVisible || reducedMotion) return;
    const timer = window.setInterval(() => {
      setPhoneType((current) => {
        const index = PHONE_TYPES.findIndex(({ type }) => type === current);
        return PHONE_TYPES[(index + 1) % PHONE_TYPES.length].type;
      });
    }, 5_000);
    return () => window.clearInterval(timer);
  }, [hovered, focused, inView, pageVisible, reducedMotion, selectedType]);

  return (
    <div className="phone-card" aria-label="IT-DA 모바일 추천 화면 미리보기">
      <div className="blob" aria-hidden="true"></div>
      <div
        className="phone phone-preview"
        ref={phoneRef}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        onFocus={() => setFocused(true)}
        onBlur={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget)) setFocused(false);
        }}
      >
        <div className="screen">
          <div className="screen-top">
            <span>IT-DA</span>
            <span id="phoneMatch" aria-label={`${data.axisLabel} 예시 ${data.places[0].axis_value}% 일치`}>
              {data.places[0].axis_value}% 일치
            </span>
          </div>
          <div className="mini-hero phone-preview-copy" key={phoneType}>
            <PhoneTypeCopy html={data.phoneType} />
            <p id="phoneDesc">{data.phoneDesc}</p>
          </div>
          <div role="group" aria-label="휴대폰 여행 유형 선택">
            {PHONE_TYPES.map(({ type, icon, label, description }) => (
              <button
                className={`type-card${phoneType === type ? " is-active" : ""}`}
                key={type}
                type="button"
                aria-pressed={phoneType === type}
                onClick={() => setPhoneType(type)}
              >
                <span className="type-icon" aria-hidden="true">{icon}</span>
                <span><strong>{label}</strong><span>{description}</span></span>
              </button>
            ))}
          </div>
          <div className="match">
            <strong className="phone-preview-copy" key={phoneType}>{data.places[0].name} · {data.axisLabel}</strong>
            <div className="bar" aria-hidden="true">
              <i id="matchBar" style={{ transform: `scaleX(${data.places[0].axis_value / 100})` }}></i>
            </div>
            <p id="matchText">선택한 유형을 가정한 일치도 예시예요. 나의 일치도는 테스트 후 확인할 수 있어요.</p>
          </div>
        </div>
      </div>
    </div>
  );
}

export function UpstreamMainPage() {
  const [openMenu, setOpenMenu] = useState(false);
  const [activeTypeReason, setActiveTypeReason] = useState(0);

  useEffect(() => {
    const interval = window.setInterval(() => {
      setActiveTypeReason((current) => (current + 1) % 3);
    }, 3000);

    return () => window.clearInterval(interval);
  }, []);
  const [activeSection, setActiveSection] = useState<string | null>(null);
  const [selectedType, setSelectedType] = useState<keyof typeof RECOMMENDATIONS>("rest");
  const rootRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const interval = window.setInterval(() => {
      setSelectedType((current) => {
        const index = RECOMMENDATION_TYPES.indexOf(current);
        return RECOMMENDATION_TYPES[(index + 1) % RECOMMENDATION_TYPES.length]!;
      });
    }, 3000);

    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    const saved = readUpstreamPreference();
    if (saved?.type && saved.type in RECOMMENDATIONS) {
      setSelectedType(saved.type as keyof typeof RECOMMENDATIONS);
    }
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

  useEffect(() => {
    const root = rootRef.current;
    if (root === null) return;
    const header = root.querySelector<HTMLElement>(".site-header");
    const sections = Array.from(root.querySelectorAll<HTMLElement>("main > section"));
    let frame: number | null = null;

    const updateActiveSection = () => {
      frame = null;
      const headerHeight = header?.getBoundingClientRect().height ?? 0;
      root.style.setProperty("--main-header-height", `${headerHeight}px`);
      let current: string | null = null;
      for (const section of sections) {
        if (section.getBoundingClientRect().top > headerHeight + 24) break;
        current = MAIN_NAV_ITEMS.some(({ id }) => id === section.id) ? section.id : null;
      }
      setActiveSection(current);
    };
    const scheduleUpdate = () => {
      if (frame === null) frame = window.requestAnimationFrame(updateActiveSection);
    };
    // Reveal transforms can finish after scrolling stops, changing section bounds.
    root.addEventListener("transitionend", scheduleUpdate);
    window.addEventListener("scroll", scheduleUpdate, { passive: true });
    window.addEventListener("resize", scheduleUpdate);
    window.addEventListener("hashchange", scheduleUpdate);
    const resizeObserver = typeof ResizeObserver === "undefined"
      ? null : new ResizeObserver(scheduleUpdate);
    resizeObserver?.observe(root);
    if (header !== null) resizeObserver?.observe(header);
    updateActiveSection();

    return () => {
      root.removeEventListener("transitionend", scheduleUpdate);
      window.removeEventListener("scroll", scheduleUpdate);
      window.removeEventListener("resize", scheduleUpdate);
      window.removeEventListener("hashchange", scheduleUpdate);
      resizeObserver?.disconnect();
      if (frame !== null) window.cancelAnimationFrame(frame);
    };
  }, []);


  return (
    <div className="up-root">
      <div className="up-main" ref={rootRef as React.RefObject<HTMLDivElement>}>
        <header className="site-header">
          <div className="wrap nav">
            <a href="/" className="logo main-page-logo" aria-label="IT-DA 메인으로 이동">
              <img className="logo-mark" src="/itda-logo-icon.png" alt="" />
              <strong className="logo-wordmark">IT-DA</strong>
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
              {MAIN_NAV_ITEMS.map(({ id, label }) => (
                <a
                  key={id}
                  href={`#${id}`}
                  className={activeSection === id ? "active" : undefined}
                  aria-current={activeSection === id ? "location" : undefined}
                  onClick={() => setOpenMenu(false)}
                >
                  {label}
                </a>
              ))}
            </nav>
            <a href="/start" className="nav-cta">시작하기</a>
          </div>
        </header>

        <main>
          <section className="hero reveal visible">
            <div className="wrap hero-grid">
              <div>
                <div className="badge"><span></span> 전국 관광데이터 기반 개인 맞춤 여행 큐레이션</div>
                <h1>
                  <span className="hero-title-line">가장 나다운 여행과</span>
                  <span className="hero-title-line">
                    <span className="gradient-text">진짜 맞는 장소</span>를 잇다
                  </span>
                </h1>
                <p>
                  <strong className="hero-copy-emphasis">당신은 어떤 여행에서 진짜다움을 느끼나요?</strong><br />
                  테스트와 사진을 통해 추구하는 여행 경험을 알아보세요.<br />
                  그에 맞는 장소를 연결해 드립니다.
                </p>

              </div>
              <PhonePreview selectedType={selectedType} />
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
                <div className={`type-visual__reasons type-visual__reasons--${activeTypeReason}`}>
                  <span className={activeTypeReason === 0 ? "is-active" : undefined}>장소에 담긴 이야기에</span>
                  <span className={activeTypeReason === 1 ? "is-active" : undefined}>분위기와 이미지에</span>
                  <span className={activeTypeReason === 2 ? "is-active" : undefined}>또는 조용히 머무는 시간에</span>
                </div>
                <strong className="type-visual__word type-visual__word--end">끌립니다.</strong>
              </div>
              <p className="type-summary">IT-DA는 이러한 차이를 세 가지 여행 경험 유형으로 나누어 살펴봅니다.</p>
              <div className="cards">
                <article className="card"><div className="icon orange">原</div><h3>대상·원형형</h3><p>관광 대상이 지닌 원형과 고유한 특성, 그 안에 담긴 역사적·문화적 가치를 중요하게 여기는 여행자를 위한 유형입니다.</p></article>
                <article className="card"><div className="icon blue">像</div><h3>의미·이미지형</h3><p>장소가 가진 분위기와 이미지, 미디어와 콘텐츠를 통해 형성된 의미를 중요하게 여기는 여행자를 위한 유형입니다.</p></article>
                <article className="card"><div className="icon green">我</div><h3>자기·몰입형</h3><p>일상에서 벗어나 온전히 자신만의 시간을 보내며 휴식과 몰입의 경험을 중요하게 여기는 여행자를 위한 유형입니다.</p></article>
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
              <div className="flow flow--four">
                <div className="step"><div className="num">01</div><strong>취향 입력</strong><p>테스트 또는 사진 업로드로 원하는 여행 분위기를 표현합니다.</p></div>
                <div className="step"><div className="num">02</div><strong>데이터 수집</strong><p>관광지 설명, 위치, 사진, 오디오 가이드 정보를 불러옵니다.</p></div>
                <div className="step"><div className="num">03</div><strong>분위기 분석</strong><p>사진은 경험 유형 판정이 아닌 감각적 분위기 신호로만 활용합니다.</p></div>
                <div className="step"><div className="num">04</div><strong>추천 제공</strong><p>유사한 분위기의 관광지와 추천 이유를 함께 안내합니다.</p></div>
              </div>
            </div>
          </section>

          <section id="demo" className="reveal">
            <div className="wrap demo">
              <div className="quiz">
                <h3>추천 장소 미리보기</h3>
                <p>공개 관광지 {examples.place_count.toLocaleString("ko-KR")}곳에서 고른 실제 장소예요.<br/>나의 추천 순위는 테스트 후 달라져요.</p>
                <button
                  className={selectedType === "history" ? "choice active" : "choice"}
                  type="button"
                  data-type="history"
                  aria-pressed={selectedType === "history"}
                  onClick={() => setSelectedType("history")}
                >
                  <i></i><span>장소 고유의 가치와 원래의 모습을 경험할 수 있는 공간</span>
                </button>
                <button
                  className={selectedType === "image" ? "choice active" : "choice"}
                  type="button"
                  data-type="image"
                  aria-pressed={selectedType === "image"}
                  onClick={() => setSelectedType("image")}
                >
                  <i></i><span>사진으로 남기고 싶은 감성적인 장소</span>
                </button>
                <button
                  className={selectedType === "rest" ? "choice active" : "choice"}
                  type="button"
                  data-type="rest"
                  aria-pressed={selectedType === "rest"}
                  onClick={() => setSelectedType("rest")}
                >
                  <i></i><span>조용히 걷고 머물 수 있는 차분한 분위기</span>
                </button>
                <a className="test-link" href="/start">12문항 취향 테스트로 자세히 보기</a>
              </div>
              <div className="result">
                {/* Shared grid cell reserves the tallest example at each viewport without clipping text. */}
                {RECOMMENDATION_TYPES.map(type => {
                  const data = RECOMMENDATIONS[type];
                  const active = selectedType === type;
                  const place = data.places[0];
                  return <div className="result-preview" key={type} aria-hidden={!active} inert={!active}>
                    <h2 id={active ? "resultTitle" : undefined}>{data.title}</h2>
                    <p className="preview-date">공개 자료 기준 {examples.release_created_at.slice(0, 10)}</p>
                    <div className="place-list" id={active ? "recommendations" : undefined}>
                      <article className="place">
                        <PlacePhotos name={place.name} photos={[place.photo]} gallery={false} captionMode="source-only" />
                        <div className="place-info">
                          <span className="tag">{data.axisLabel} {place.axis_value}점</span>
                          <h3>{place.name}</h3>
                          <p className="place-region">{place.region} · {place.category}</p>
                          <div className="place-address"><span>주소</span><p>{place.address}</p></div>
                          <a className="place-map" href={placeMapUrl(place.name, place.address)} target="_blank" rel="noreferrer">지도에서 보기</a>
                        </div>
                      </article>
                    </div>
                  </div>;
                })}
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
          <a href="#demo">추천</a>
        </nav>

        <footer>
          <div className="wrap">© 2026 IT-DA. Tourism Data Curation Service.</div>
        </footer>
      </div>
    </div>
  );
}
