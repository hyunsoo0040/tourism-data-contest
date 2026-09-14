"use client";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, useLocation, useNavigate, useParams } from "../../app/react-router-dom";
import { api, ensureSession, escapeId, json, JourneyError, type Axis, type Definition, type Detail, type Facet, type Info, type Intent, type Photo, type Run, type Submission } from "./api";
import styles from "./Journey.module.css";
import { PlacePhotos } from "./PlacePhotos";
import { PlaceInformation } from "./PlaceInformation";
import { PhotoCameraIcon, PhotoWorkspace } from "../photo/PhotoWorkspace";
import { afterImportance, emptyOptions, FacilityControls, photoConflict, PreferenceControls, PersonalExperienceControls, restoreOptions, type PersonalRatings } from "./Preferences";

const labels: Record<Axis,string> = { H:"대상•원형형", E:"의미•이미지형", R:"자기•몰입형" };
const facetLabels: Record<string,string> = { "H.a":"원형·유산과의 접촉","H.b":"역사·출처의 구체성","H.c":"전통의 실제 지속","H.d":"원형 맥락의 탐구","E.a":"공유되는 상징·의미","E.b":"매체를 통한 이미지 유통","E.c":"이미지의 시각적 표현","E.d":"이미지의 체험·재현","R.a":"일상에서 벗어날 여지","R.b":"회복을 지원하는 환경","R.c":"참여·도전·몰입","R.d":"관계·자기표현" };
const sourceLabels:Record<string,string>={KorService2:"한국관광공사",Odii:"오디오 해설",PhotoGalleryService1:"관광사진",APIFY_INSTAGRAM:"인스타그램"};
const roleLabels:Record<string,string>={OFFICIAL_DESCRIPTION:"공식 설명",OFFICIAL_NARRATIVE:"공식 해설",OFFICIAL_PHOTO:"공식 사진",OFFICIAL_PROMOTION:"관광 홍보",ADVERTISEMENT:"광고 표시 게시물",VISITOR_POST:"방문자 게시물",UNCLASSIFIED:"작성 주체 미확인"};
const moodLabels: Record<string,string> = { greenery:"녹지",water:"물",open_composition:"트인 구도",traditional_appearance:"전통적 외관",contemporary_design:"현대적 디자인",warm_light:"따뜻한 빛",vivid_color:"선명한 색",night_lighting:"야간 조명" };
function message(error: unknown): string { return error instanceof Error ? error.message : "요청을 완료하지 못했습니다."; }
function Shell({children}: {children:ReactNode}) { return <div className={styles.root}><div className={styles.wrap}><header className={styles.header}><Link className={styles.brand} to="/">IT-DA</Link><nav className={styles.nav}><Link to="/trip">새 여행 기대</Link><Link to="/trip/saved">저장한 장소</Link></nav></header><main className={styles.main}>{children}</main><footer className={styles.footer}>이번 여행의 기대와 장소의 근거를 연결합니다. 미확인은 낮은 점수와 구분합니다.</footer></div></div>; }
function ErrorBox({text}: {text:string|null}) { return text ? <p className={styles.error} role="alert">{text}</p> : null; }
function Axes({values}: {values:Partial<Record<Axis,number|null>>}) { return <div className={styles.axisList}>{(["H","E","R"] as const).map(axis=><div className={styles.axis} key={axis}><span>{labels[axis]}</span><div className={styles.bar}><span style={{transform:`scaleX(${(values[axis]??0)/100})`,background:`var(--axis-${axis==="H"?"history":axis==="E"?"emotion":"rest"})`}} /></div><b>{values[axis]??"미확인"}</b></div>)}</div>; }

export function TripPage() {
  const navigate=useNavigate();
  const [definition,setDefinition]=useState<Definition|null>(null),[info,setInfo]=useState<Info|null>(null);
  const [answers,setAnswers]=useState<Partial<Record<Facet,number|null>>>({}),[step,setStep]=useState(0),[region,setRegion]=useState("");
  const [options,setOptions]=useState(emptyOptions);
  const [photo,setPhoto]=useState<Photo|null>(null),[chosen,setChosen]=useState<string[]>([]),[urls,setUrls]=useState<string[]>([]);
  const [busy,setBusy]=useState(false),[error,setError]=useState<string|null>(null),[loading,setLoading]=useState(true);
  const heading=useRef<HTMLHeadingElement>(null), files=useRef<HTMLInputElement>(null), pending=useRef<{profile:string;run:string}|null>(null);
  useEffect(()=>{let live=true;Promise.all([api<Definition>("/definition"),api<Info>("/info")]).then(([d,i])=>{if(live){setDefinition(d);setInfo(i);try{const saved=JSON.parse(sessionStorage.getItem("itda.authenticity.draft")??"null");if(saved?.sha===d.questionnaire_sha256&&saved.answers&&typeof saved.answers==="object"){const valid=Object.fromEntries(Object.entries(saved.answers).filter(([k,v])=>d.questions.some(q=>q.key===k)&&d.choices.some(c=>c.value===v)));setAnswers(valid);setOptions(restoreOptions(saved.options,valid));setRegion(i.regions.some(r=>r.code===saved.region)?saved.region:"");}}catch{/* fresh form */}}}).catch(e=>live&&setError(message(e))).finally(()=>live&&setLoading(false));return()=>{live=false};},[]);
  useEffect(()=>{if(definition)try{sessionStorage.setItem("itda.authenticity.draft",json({sha:definition.questionnaire_sha256,answers,region,options}));}catch{/* page retains state */}},[answers,region,options,definition]);
  useEffect(()=>{heading.current?.focus();window.scrollTo({top:0});},[step]);
  useEffect(()=>()=>urls.forEach(URL.revokeObjectURL),[urls]);
  const questions=definition?.questions.slice(step*4,step*4+4)??[];
  const complete=questions.every(q=>Object.prototype.hasOwnProperty.call(answers,q.key));
  async function upload() {
    const selected=Array.from(files.current?.files??[]);if(!selected.length)return;
    if(selected.length>3||selected.some(f=>f.size>10*1024*1024)){setError("사진은 최대 3장, 한 장당 10MB까지 선택할 수 있어요.");return;}
    setBusy(true);setError(null);
    try{await ensureSession();const form=new FormData();selected.forEach(f=>form.append("files",f));const p=await api<Photo>("/photos",{method:"POST",body:form});setUrls(selected.map(f=>URL.createObjectURL(f)));setPhoto(p);setChosen([]);pending.current=null;}
    catch(e){setError(message(e));}finally{setBusy(false);if(files.current)files.current.value="";}
  }
  async function removePhoto(){if(!photo)return;setBusy(true);try{await api(`/photos/${escapeId(photo.photo_id)}`,{method:"DELETE"});setPhoto(null);setChosen([]);setUrls([]);}catch(e){setError(message(e));}finally{setBusy(false);}}
  async function recommend(usePhoto:boolean) {
    if(!definition)return;setBusy(true);setError(null);
    try{
      await ensureSession();let confirmed:Photo|null=null;
      if(usePhoto&&photo){
        const dimensions=photo.batches.flatMap(b=>b.candidates.filter(c=>chosen.includes(c.candidate_id)).map(c=>c.observation.dimension));
        if(photoConflict(dimensions,options.avoid))throw new Error("선택한 사진 분위기가 피하기 설정과 겹쳐요. 분위기 선택을 해제하거나 이전 단계에서 피하기를 수정해 주세요.");
        if(!chosen.length)throw new Error("반영할 분위기를 하나 이상 선택하거나 사진 없이 진행해 주세요.");confirmed=await api<Photo>(`/photos/${escapeId(photo.photo_id)}/confirm`,{method:"POST",body:json({candidate_ids:chosen})});setPhoto(confirmed);}
      pending.current??={profile:crypto.randomUUID(),run:crypto.randomUUID()};
      const body:Submission={request_id:pending.current.profile,questionnaire_sha256:definition.questionnaire_sha256,answers:answers as Submission["answers"],requirements:{region_code:region||null,required_facilities:options.facilities},desired_levels:options.desired,avoid:options.avoid,visual_targets:confirmed?.targets??{},visual_input_kind:confirmed?"CONFIRMED_PHOTO":"NONE",photo_receipt_sha256:confirmed?.receipt_sha256??null};
      const profile=await api<Intent>("/profiles",{method:"POST",body:json(body)});
      const result=await api<Run>("/runs",{method:"POST",body:json({profile_id:profile.profile_id,request_id:pending.current.run})});
      navigate(`/trip/results/${result.run_sha256}`);
    }catch(e){if(e instanceof JourneyError&&(e.status===409||e.status===401))pending.current=null;setError(message(e));}finally{setBusy(false);}
  }
  if(loading)return <Shell><p className={styles.spinner} role="status">여행 기대 문항을 불러오고 있어요.</p></Shell>;
  if(!definition)return <Shell><h1>여행을 준비하지 못했어요</h1><ErrorBox text={error}/><button className={styles.secondary} onClick={()=>window.location.reload()}>다시 불러오기</button></Shell>;
  return <Shell><h1 ref={heading} tabIndex={-1}>{step<3?"이번 여행에서 원하는 순간":"원하는 분위기를 더해보세요"}</h1><p className={styles.muted}>{step<3?"경험마다 원하는 정도를 골라주세요. 여러 경험을 모두 원해도 괜찮아요.":"사진은 선택 사항이에요. 분석한 분위기 중 실제로 원하는 것만 골라주세요."}</p>
    <ol className={styles.steps} aria-label="여행 기대 입력 단계">{["대상•원형형","의미•이미지형","자기•몰입형","사진·추천"].map((s,i)=><li key={s} aria-current={i===step?"step":undefined}>{s}</li>)}</ol>
    {info?.scope==="DEVELOPMENT"&&<p className={styles.notice}>현재 개발 표본 {info.places}곳을 연결한 화면입니다.</p>}
    <ErrorBox text={error}/>
    {step<3?<><h2>{labels[(["H","E","R"] as const)[step]!]}</h2>{questions.map(q=><fieldset key={q.key} className={styles.field}><legend>{q.text}</legend><div className={styles.options}>{definition.choices.map(c=><label className={styles.option} key={c.value??"unknown"}><input type="radio" name={q.key} value={c.value??"unknown"} checked={Object.prototype.hasOwnProperty.call(answers,q.key)&&answers[q.key]===c.value} onChange={()=>{setAnswers(a=>({...a,[q.key]:c.value}));setOptions(o=>afterImportance(o,q.key,c.value));pending.current=null;}}/>{c.label}</label>)}</div><PreferenceControls facet={q.key} label={facetLabels[q.key]!} importance={answers[q.key]} options={options} onChange={o=>{setOptions(o);pending.current=null;}} onAvoid={strength=>{
      const avoid={...options.avoid},desired={...options.desired};if(strength){avoid[q.key]=strength;delete desired[q.key];setAnswers(a=>({...a,[q.key]:0}));}else delete avoid[q.key];
      setOptions({...options,avoid,desired});pending.current=null;
    }}/></fieldset>)}<div className={styles.actions}><button className={styles.secondary} disabled={step===0} onClick={()=>setStep(s=>s-1)}>이전</button><button className={styles.primary} disabled={!complete} onClick={()=>{setError(null);setStep(s=>s+1);}}>다음</button></div></>:
      <><label className={styles.control}>여행 지역<select value={region} onChange={e=>{setRegion(e.target.value);pending.current=null;}}><option value="">전국에서 찾기</option>{info?.regions.map(r=><option key={r.code} value={r.code}>{r.name}</option>)}</select></label>
      <FacilityControls options={options} onChange={o=>{setOptions(o);pending.current=null;}}/>
      <div className={`${styles.photoStage} up-photo`}><PhotoWorkspace headingLevel={2} headingId="trip-photo-heading"><section className={`profile-state photo-picker${urls.length ? " photo-picker--has-rows" : ""}`}><h3>사진으로 전하는 취향</h3><p className={styles.small}>최대 3장 · JPG, PNG, WebP · 장당 10MB. 위치 메타데이터를 제거하고 분위기를 분석한 뒤 서버에 원본을 보관하지 않습니다.</p>
      <input ref={files} type="file" aria-label="여행 분위기 참고 사진" className="photo-picker__input" accept="image/jpeg,image/png,image/webp" multiple disabled={busy||!info?.photo_enabled} onChange={upload} />
      <button type="button" className="button button--secondary photo-picker__trigger" disabled={busy||!info?.photo_enabled} onClick={()=>files.current?.click()}><span className="photo-picker__trigger-icon"><PhotoCameraIcon /></span><span className="photo-picker__trigger-copy"><strong>{urls.length ? "사진 다시 고르기" : "사진 고르기"}</strong><small>내 기기에서 여행 사진을 선택해 주세요</small></span></button>
      {!info?.photo_enabled&&<p className={styles.small}>현재 사진 분석을 준비 중입니다. 사진 없이 추천을 받을 수 있습니다.</p>}
      <div className={styles.preview}>{urls.map((url,i)=><img key={url} src={url} alt={`내가 선택한 분위기 참고 사진 ${i+1}`}/>)}</div>
      {photo&&<><p>반영할 분위기를 직접 선택해 주세요. 사진의 역사적 진위나 실제 혼잡을 판단한 결과는 아닙니다.</p><div className={styles.photoChoices}>{photo.batches.flatMap((b,i)=>b.candidates.filter(c=>c.observation.state==="OBSERVED").map(c=><label key={c.candidate_id}><input type="checkbox" disabled={busy} checked={chosen.includes(c.candidate_id)} onChange={e=>{setChosen(v=>e.target.checked?[...v,c.candidate_id]:v.filter(id=>id!==c.candidate_id));pending.current=null;}}/>사진 {i+1} · {moodLabels[c.observation.dimension]} {c.observation.level}/4</label>))}</div><button className={styles.secondary} onClick={removePhoto} disabled={busy}>사진 분석 결과 삭제</button><p className={styles.small}>서버 원본 보관: 없음 · 선택한 분위기만 여행 기대에 반영합니다.</p></>}
      </section><div className={`${styles.actions} photo-action-bar`}><button className={`${styles.secondary} button button--secondary`} disabled={busy} onClick={()=>setStep(2)}>이전</button><div className={styles.resultButtons}><button className={`${photo?styles.secondary:styles.primary} button ${photo?"button--secondary":"button--primary"}`} disabled={busy} onClick={()=>recommend(false)}>사진 없이 추천 보기</button>{photo&&<button className={`${styles.primary} button button--primary`} disabled={busy||!chosen.length} onClick={()=>recommend(true)}>선택한 분위기로 추천 보기</button>}</div></div>{busy&&<p role="status" className={styles.spinner}>입력과 근거를 확인하고 있어요.</p>}</PhotoWorkspace></div></>}
    </Shell>;
}

function ResultReason({detail}: {detail:Detail|undefined}) {
  if(!detail)return <p className={styles.small} role="status">장소의 연결 근거를 불러오고 있어요.</p>;
  const ordered=detail.item.components.filter(c=>c.compared).sort((a,b)=>b.weight-a.weight);
  for(const component of ordered){
    const facet=detail.facets.find(f=>f.key===component.facet);
    if(!facet)continue;
    for(const contribution of facet.contributions){
      for(const id of contribution.evidence_ids){
        const evidence=detail.evidence.find(e=>e.evidence_id===id);
        const quote=evidence?.facet_quotes.find(q=>q.facet===facet.key);
        if(quote&&evidence)return <div data-recommendation-evidence><p><b>{facetLabels[facet.key]}</b> — “{quote.quote.slice(0,160)}{quote.truncated||quote.quote.length>160?"…":""}”</p><p className={styles.small}>{sourceLabels[evidence.provider]??evidence.provider} · {roleLabels[evidence.role]??evidence.role}</p></div>;
        if(contribution.channel==="PHOTO"&&typeof evidence?.appearance?.reason==="string")return <div data-recommendation-evidence><p><b>{facetLabels[facet.key]}</b> — 사진에서 {evidence.appearance.reason}</p><p className={styles.small}>{sourceLabels[evidence.provider]??evidence.provider} · {roleLabels[evidence.role]??evidence.role}</p></div>;
      }
    }
  }
  return <p className={styles.small}>연결에 사용한 항목별 판단과 미확인 사항을 상세 근거에서 확인해 주세요.</p>;
}

function RecommendationPlace({ item, runId, saved, compared, compareDisabled, onSave, onCompare }: {
  item: Run["items"][number]; runId: string; saved: boolean; compared: boolean;
  compareDisabled: boolean; onSave: () => void; onCompare: () => void;
}) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setDetail(null); setError(null);
    api<Detail>(`/runs/${escapeId(runId)}/places/${escapeId(item.place_id)}`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setDetail(value); })
      .catch(reason => { if (!controller.signal.aborted) setError(message(reason)); });
    return () => controller.abort();
  }, [runId, item.place_id, attempt]);
  const href = `/trip/results/${runId}/places/${escapeId(item.place_id)}`;
  return <article className={styles.result} data-details-loaded={Boolean(detail)}>
    <PlacePhotos key={item.place_id} name={item.name_ko} photos={detail?.photos ?? []} loading={!detail && !error} unavailable={Boolean(error)} />
    <div>
      <div className={styles.resultTop}>
        <h2><Link to={href}>{item.rank}. {item.name_ko}</Link></h2>
        <span>기대 연결 {item.score}</span>
      </div>
      <p className={styles.small}>{item.region_name} · {item.category}</p>
      {detail && <PlaceInformation detail={detail} />}
      {error && <div className={styles.notice} role="status">
        <p>이 장소의 사진과 정보를 불러오지 못했어요. 추천 결과는 유지됩니다.</p>
        <button className={styles.secondary} onClick={() => setAttempt(value => value + 1)}>{item.name_ko} 정보 다시 불러오기</button>
      </div>}
      <Axes values={item.axes} />
      {!error && <ResultReason detail={detail ?? undefined} />}
      {item.warnings.length > 0 && <p className={styles.small}>일부 기대 항목은 미확인입니다. 상세 근거에서 확인해 주세요.</p>}
      <div className={styles.resultButtons}>
        <button className={styles.secondary} onClick={onSave}>{saved ? "저장 취소" : "장소 저장"}</button>
        <button className={styles.secondary} disabled={compareDisabled} onClick={onCompare}>{compared ? "비교에서 빼기" : "비교에 담기"}</button>
        <Link to={href}>사진·장소 정보</Link><Link to={`${href}#evidence`}>상세 근거</Link>
      </div>
    </div>
  </article>;
}

export function ResultsPage() {
  const { runId } = useParams();
  const [run, setRun] = useState<Run | null>(null);
  const [compare, setCompare] = useState<string[]>([]);
  const [saved, setSaved] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    setRun(null); setError(null); setSaved([]); setCompare([]);
    if (!runId) return;
    api<Run>(`/runs/${escapeId(runId)}`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setRun(value); })
      .catch(reason => { if (!controller.signal.aborted) setError(message(reason)); });
    api<{ run_sha256: string; place_id: string }[]>("/saved", { signal: controller.signal })
      .then(rows => { if (!controller.signal.aborted) setSaved(rows.filter(row => row.run_sha256 === runId).map(row => row.place_id)); })
      .catch(() => {});
    return () => controller.abort();
  }, [runId]);
  async function save(id: string) {
    try {
      await api(`/runs/${escapeId(runId!)}/places/${escapeId(id)}/saved`, { method: "PUT", body: json({ saved: !saved.includes(id) }) });
      setSaved(value => value.includes(id) ? value.filter(item => item !== id) : [...value, id]);
    } catch (reason) { setError(message(reason)); }
  }
  return <Shell>
    <h1>내 기대와 연결되는 장소</h1>
    <p className={styles.muted}>지역과 장소 소개, 실제 사진을 함께 살펴보세요. 높은 점수는 장소의 우열이 아니라 이번 입력에 대한 연결 정도입니다.</p>
    <ErrorBox text={error} />
    {!run && !error && <p role="status">추천 결과를 불러오고 있어요.</p>}
    {run?.state === "EMPTY" && <div className={styles.notice}><h2>지금 조건으로는 충분한 근거를 찾지 못했어요</h2><p>중요한 경험의 근거가 없는 장소를 대신 추천하지 않았습니다. 지역이나 기대를 조정해 주세요.</p><Link to="/trip">여행 기대 수정</Link></div>}
    {run?.state === "LIMITED" && <p className={styles.notice}>확인 가능한 근거를 갖춘 {run.result_count}곳을 찾았습니다. 다섯 곳을 임의로 채우지 않았어요.</p>}
    {run?.items.map(item => <RecommendationPlace key={`${runId}:${item.place_id}`} item={item} runId={runId!}
      saved={saved.includes(item.place_id)} compared={compare.includes(item.place_id)}
      compareDisabled={!compare.includes(item.place_id) && compare.length >= 3}
      onSave={() => save(item.place_id)}
      onCompare={() => setCompare(value => value.includes(item.place_id) ? value.filter(id => id !== item.place_id) : [...value, item.place_id])} />)}
    {compare.length > 0 && <div className={styles.tray}><span>{compare.length}곳 비교에 담음</span><Link to={`/trip/results/${runId}/compare?places=${encodeURIComponent(compare.join(","))}`}>장소 비교하기</Link></div>}
  </Shell>;
}

export function DetailPage() {
  const {runId,placeId}=useParams();const [detail,setDetail]=useState<Detail|null>(null),[error,setError]=useState<string|null>(null),[visited,setVisited]=useState(false),[note,setNote]=useState(""),[sent,setSent]=useState(false);
  const [ratings,setRatings]=useState<PersonalRatings>({}),[recording,setRecording]=useState(false);
  const feedbackId=useRef<string|null>(null);
  function edit(){feedbackId.current=null;setSent(false);setError(null);}
  useEffect(()=>{let live=true;setDetail(null);setVisited(false);setRatings({});setNote("");setSent(false);setError(null);feedbackId.current=null;api<Detail>(`/runs/${escapeId(runId!)}/places/${escapeId(placeId!)}`).then(d=>live&&setDetail(d)).catch(e=>live&&setError(message(e)));return()=>{live=false};},[runId,placeId]);
  async function feedback(){setRecording(true);setError(null);feedbackId.current??=crypto.randomUUID();try{await api(`/runs/${escapeId(runId!)}/places/${escapeId(placeId!)}/feedback`,{method:"POST",body:json({request_id:feedbackId.current,visited,note,expectations_met:visited?ratings:{}})});setSent(true);}catch(e){setError(message(e));}finally{setRecording(false);}}
  return <Shell><Link to={`/trip/results/${runId}`}>추천 목록으로</Link><ErrorBox text={error}/>{!detail&&!error?<p role="status">장소 근거를 불러오고 있어요.</p>:detail&&<><h1 style={{marginTop:24}}>{detail.item.name_ko}</h1><p className={styles.small}>{detail.item.region_name} · {detail.item.category}</p><div className={styles.detailHero}><div><h2>장소 소개</h2><PlaceInformation detail={detail} expanded /><Axes values={detail.item.axes}/></div><PlacePhotos key={detail.item.place_id} name={detail.item.name_ko} photos={detail.photos} size="full" /></div><p className={styles.small}>{detail.limitations.join(" ")}</p><h2 id="evidence">이 점수의 근거</h2>{detail.facets.map(f=><details className={styles.facet} key={f.key}><summary>{facetLabels[f.key]} · {f.value===null?"미확인":`${f.value}점`}</summary><p>{f.contributions.some(c=>c.channel==="PHOTO")&&!f.contributions.some(c=>c.channel==="TEXT")?"텍스트 판단이 미확인인 항목을 사진에서 직접 보이는 특성으로 보완했습니다.":f.reason}</p>{f.contributions.map(c=><div key={c.channel}><h4>{c.channel==="TEXT"?"텍스트 근거":c.channel==="PHOTO"?"사진 분위기": "SNS 이미지 유통"} · 기여 {c.weight_bp/100}%</h4>{c.evidence_ids.map(id=>{const e=detail.evidence.find(x=>x.evidence_id===id);const quotes=e?.facet_quotes.filter(q=>q.facet===f.key)??[];return e?<div key={id}>{quotes.length?quotes.map((q,i)=><blockquote key={i} className={styles.quote}>{q.quote}{q.truncated?"… (인용 일부)":""}</blockquote>):e.appearance?<p>{String(e.appearance.reason??"사진에서 관찰한 분위기")}</p>:e.reported_count!==null?<p>관측된 태그 게시물 수 {e.reported_count.toLocaleString()}</p>:null}<p className={styles.small}>{sourceLabels[e.provider]??e.provider} · {roleLabels[e.role]??e.role} · 수집 {e.retrieved_at.slice(0,10)} {e.uri&&<a href={e.uri} target="_blank" rel="noreferrer">출처 열기</a>}</p></div>:null;})}</div>)}</details>)}<section className={styles.feedback}><h2>내 여행 기록</h2><p className={styles.small}>이 기록은 내 경험을 남기는 기능이며, 현재 연구 평가로 집계하지 않습니다.</p><label><input type="checkbox" checked={visited} disabled={recording} onChange={e=>{edit();setVisited(e.target.checked);if(!e.target.checked)setRatings({});}}/> 이 장소를 방문했어요</label>{visited&&<><p className={styles.small}>방문했을 때 느낀 경험을 선택적으로 남겨주세요. 장소의 역사 사실이나 기존 점수를 변경하지 않습니다.</p><PersonalExperienceControls ratings={ratings} disabled={recording} onChange={r=>{edit();setRatings(r);}}/></>}<label className={styles.control}>기대와 같거나 달랐던 점<textarea value={note} maxLength={500} disabled={recording} onChange={e=>{edit();setNote(e.target.value);}}/></label><button className={styles.primary} onClick={feedback} disabled={sent||recording}>{recording?"기록을 저장하고 있어요":sent?"기록을 저장했어요":"여행 기록 저장"}</button></section></>}</Shell>;
}

export function ComparePage() {
  const {runId}=useParams();const location=useLocation();const [places,setPlaces]=useState<Detail[]>([]),[error,setError]=useState<string|null>(null),[loading,setLoading]=useState(true),[retry,setRetry]=useState(0);
  useEffect(()=>{let live=true;setLoading(true);setError(null);const ids=new URLSearchParams(location.search).get("places")??"";api<{places:Detail[]}>(`/runs/${escapeId(runId!)}/compare?place_ids=${encodeURIComponent(ids)}`).then(r=>live&&setPlaces(r.places)).catch(e=>live&&setError(message(e))).finally(()=>live&&setLoading(false));return()=>{live=false};},[runId,location.search,retry]);
  return <Shell><h1>장소의 차이를 나란히</h1><p>점수와 함께 미확인 항목도 비교하세요.</p><ErrorBox text={error}/>{error&&<button className={styles.secondary} onClick={()=>setRetry(v=>v+1)}>다시 불러오기</button>}{loading?<p role="status">비교할 장소의 근거를 불러오고 있어요.</p>:!error&&!places.length?<p>비교할 장소가 없어요. 추천 목록에서 장소를 담아주세요.</p>:!error&&<div className={styles.scroll} tabIndex={0} aria-label="장소 비교 표"><table className={styles.table}><thead><tr><th>비교 항목</th>{places.map(p=><th key={p.item.place_id}>{p.item.name_ko}</th>)}</tr></thead><tbody>{(["H","E","R"] as const).map(a=><tr key={a}><th>{labels[a]}</th>{places.map(p=><td key={p.item.place_id}>{p.item.axes[a]??"미확인"}</td>)}</tr>)}<tr><th>지역</th>{places.map(p=><td key={p.item.place_id}>{p.address}</td>)}</tr><tr><th>확인할 점</th>{places.map(p=><td key={p.item.place_id}>{p.facets.filter(f=>f.value===null).map(f=>facetLabels[f.key]).join(", ")||"모든 항목에 근거가 있어요"}</td>)}</tr><tr><th>상세 근거</th>{places.map(p=><td key={p.item.place_id}><Link to={`/trip/results/${runId}/places/${escapeId(p.item.place_id)}`}>장소 살펴보기</Link></td>)}</tr></tbody></table></div>}<p><Link to={`/trip/results/${runId}`}>추천 목록으로</Link></p></Shell>;
}

export function SavedPage() {
  const [items,setItems]=useState<{run_sha256:string;place_id:string;name:string}[]>([]),[error,setError]=useState<string|null>(null),[loading,setLoading]=useState(true),[retry,setRetry]=useState(0);
  useEffect(()=>{let live=true;setLoading(true);setError(null);api<{run_sha256:string;place_id:string}[]>("/saved").then(async rows=>{const items=await Promise.all(rows.map(async row=>{const d=await api<Detail>(`/runs/${escapeId(row.run_sha256)}/places/${escapeId(row.place_id)}`);return {...row,name:d.item.name_ko};}));if(live)setItems(items);}).catch(e=>live&&setError(message(e))).finally(()=>live&&setLoading(false));return()=>{live=false};},[retry]);
  return <Shell><h1>저장한 장소</h1><ErrorBox text={error}/>{error&&<button className={styles.secondary} onClick={()=>setRetry(v=>v+1)}>다시 불러오기</button>}{loading&&<p role="status">저장한 장소를 불러오고 있어요.</p>}{!loading&&!items.length&&!error&&<p>아직 저장한 장소가 없어요. 추천 결과에서 마음에 드는 장소를 저장해 보세요.</p>}{!loading&&!error&&items.map(p=><p className={styles.facet} key={`${p.run_sha256}:${p.place_id}`}><Link to={`/trip/results/${p.run_sha256}/places/${escapeId(p.place_id)}`}>{p.name}</Link></p>)}<Link to="/trip">새 여행 기대 입력</Link></Shell>;
}
