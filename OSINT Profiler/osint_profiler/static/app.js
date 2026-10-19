"use strict";

// One local store, shared with the CLI. Report content is always rendered as text.
const state = {token:"", cases:[], inbox:[], caseId:"", data:null, tab:"overview", uploads:[], load:0};
const $ = id => document.getElementById(id);
const pretty = value => String(value || "").replaceAll("_", " ");
const fmtDate = value => value ? new Date(value).toLocaleString() : "Unknown date";
function el(tag, attrs={}, ...children) {
  const node = document.createElement(tag);
  for (const [key,value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key === "text") node.textContent = value;
    else if (value !== undefined && value !== null && value !== false) node.setAttribute(key,value === true ? "" : String(value));
  }
  for (const child of children.flat(Infinity)) if (child !== null && child !== undefined) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return node;
}
const button = (text, handler, cls="") => el("button", {type:"button", class:cls, onclick:()=>run(handler)}, text);
const badge = (text, type="") => el("span", {class:"badge "+type}, pretty(text));
const paragraph = (text, cls="") => el("p", {class:cls},text);
const empty = text => el("div",{class:"empty"},paragraph(text));
function notice(message, error=false) { $("notice").hidden=false; $("notice").className=error?"error":""; $("notice").textContent=message; }
async function run(fn) { try { return await fn(); } catch (error) { notice(error.message,true); } }
async function request(url,options={}) {
  const response = await fetch(url,{...options,credentials:"same-origin",cache:"no-store"});
  let body;
  try { body=await response.json(); } catch { throw new Error("The local server returned an unreadable response. Check the terminal and refresh."); }
  if (body.error === "subject-authorization-required") throw Object.assign(new Error(body.message), {authorization:body});
  if (!response.ok || !body.ok) throw new Error(body.error || "The request could not be completed.");
  return body.data;
}
const action = (name,args={}) => request("/api/action", {method:"POST",headers:{"Content-Type":"application/json","X-Profiler-Token":state.token},body:JSON.stringify({action:name,args})});
const caseArgs = args => ({case_id:state.caseId,...args});
const PURPOSES=["fraud-investigation","due-diligence","journalism","security-research","legal-process","missing-person","self-or-consented-check","other"];
const LEGAL_BASES=["consent","legitimate-interest","contract","legal-obligation","vital-interest","public-task","other"];
async function withAuthorization(fn) {
  try { return await fn(); } catch (error) { if (!error.authorization) throw error; await authorizeDialog(error.authorization); }
}
async function authorizeDialog(problem) {
  const text=await action("authorization_text");
  dialog("Subject authorization required",form([paragraph(problem.message,"muted"),paragraph(text.banner),el("pre",{},text.text),
    field("Subject alias (e.g. Subject A; never a name, number, email or handle)","subject_label","text","","",true),
    selectField("Purpose","purpose",PURPOSES),field("Purpose note (required for other)","purpose_note"),
    selectField("Legal basis","legal_basis",LEGAL_BASES),field("Basis note (required for other)","basis_note"),
    field("Jurisdiction","jurisdiction","text","","",true),
    field("Type exactly: "+text.phrase,"acknowledgement","text","","Case-sensitive. Nothing is recorded unless it matches.",true)],"Record authorization",async values=>{
      await action("authorize",{case_id:problem.case_id,...values});closeDialog();await refresh();notice("Authorization recorded for 180 days. Repeat the action you were attempting.");}));
}
function dialog(title, content) { const wasOpen=$("dialog").open; $("dialog-title").textContent=title; $("dialog-body").replaceChildren(content); if (!wasOpen) $("dialog").showModal(); else $("dialog-close").focus(); }
function closeDialog() { $("dialog").close(); }
let fieldNumber=0;
function field(label,name,type="text",value="",help="",required=false) {
  const id="field-"+(++fieldNumber);
  const input=type==="textarea"?el("textarea",{id,name,required}):el("input",{id,name,type,required});
  input.value=value;
  const hint=help?el("span",{id:id+"-hint",class:"field-help"},help):null;
  if(hint) input.setAttribute("aria-describedby",hint.id);
  return el("div",{class:"field"},el("label",{for:id},label),input,hint);
}
function selectField(label,name,options,value="") {
  const id="field-"+(++fieldNumber), select=el("select",{id,name});
  for(const option of options) { const [val,text]=Array.isArray(option)?option:[option,pretty(option)]; select.append(el("option",{value:val},text)); }
  if(value!=="") select.value=value;
  return el("div",{class:"field"},el("label",{for:id},label),select);
}
function form(children,label,handler) {
  const error=el("div",{class:"form-error",role:"alert",hidden:true});
  const submit=el("button",{type:"submit",class:"primary"},label);
  const node=el("form",{},children,error,el("div",{class:"actions"},submit));
  node.addEventListener("submit",async event=>{
    event.preventDefault(); error.hidden=true; submit.disabled=true; const old=submit.textContent; submit.textContent="Working…";
    try {await handler(Object.fromEntries(new FormData(node)),node);} catch(e){error.textContent=e.message;error.hidden=false;error.scrollIntoView({block:"nearest"});}
    finally {submit.disabled=false;submit.textContent=old;}
  });
  return node;
}
function table(headings,rows) { return el("div",{class:"table-wrap",tabindex:"0","aria-label":"Scrollable results table"},el("table",{},el("thead",{},el("tr",{},headings.map(h=>el("th",{scope:"col"},h)))),el("tbody",{},rows.map(r=>el("tr",{},r.map(c=>el("td",{},c))))))); }
function card(title,body,control=null) { return el("section",{class:"card"},el("div",{class:"card-head"},el("h2",{},title),control),body); }
function artifactUrl(id,preview=false) { return "/api/artifact?"+new URLSearchParams({case:state.caseId,id,...(preview?{preview:"1"}:{})}); }
function artifactLink(id,name="Download original") {return el("a",{href:artifactUrl(id),download:""},name);}
const entityLabel = id => { const e=state.data.entities.find(x=>x.id===id);return e?`${e.label} · ${e.platform || e.kind}`:id; };
const artifactName = id => state.data.artifacts.find(x=>x.id===id)?.name || id;
function renderNavigation() {
  $("case-picker").replaceChildren(el("option",{value:""},"Select a case…"),...state.cases.filter(c=>!c.legacy).map(c=>el("option",{value:c.id},c.title)));
  $("case-picker").value=state.caseId;
  $("home-button").setAttribute("aria-current",state.caseId?"false":"page");
  $("case-nav").replaceChildren();
  if(state.caseId) for(const [name,label] of [["overview","Overview"],["findings","Findings & review"],["connections","Connections"],["evidence","Evidence & imports"],["activity","Activity & scans"]]) {
    const b=button(label,()=>{state.tab=name;render();$("main").focus({preventScroll:true});},"nav-button"); b.setAttribute("aria-current",state.tab===name?"page":"false"); $("case-nav").append(b);
  }
  $("breadcrumb").textContent=state.caseId?`Cases / ${state.caseId} / ${pretty(state.tab)}`:"Workspace / Cases & imports";
}
async function bootstrap() {const data=await request("/api/bootstrap");state.cases=data.cases;state.inbox=data.inbox;}
async function refresh() {if(!state.token)state.token=(await request("/api/session")).token;await bootstrap();if(state.caseId) state.data=await request("/api/case/"+encodeURIComponent(state.caseId));render();}
async function openCase(id,tab="overview") {
  const serial=++state.load;
  if(!id){state.caseId="";state.data=null;history.replaceState(null,"","/");render();return;}
  const data=await request("/api/case/"+encodeURIComponent(id));
  if(serial!==state.load)return;
  state.caseId=id;state.data=data;state.tab=tab;history.replaceState(null,"","/?case="+encodeURIComponent(id));render();
}
function render() {
  renderNavigation();
  const main=$("main"); main.replaceChildren();
  if(!state.caseId){renderHome(main);return;}
  if(!state.data){main.append(empty("Loading the case…"));return;}
  main.append(el("div",{class:"page-heading"},el("div",{},el("div",{class:"eyebrow"},"CASE / "+state.caseId),el("h1",{},state.data.case.title),paragraph(state.data.case.question,"muted")),el("div",{class:"actions"},badge(state.data.case.status),button("Edit case",editCase),button("Export profile",exportCase))));
  ({overview:renderOverview,findings:renderFindings,connections:renderConnections,evidence:renderEvidence,activity:renderActivity})[state.tab](main);
}
function newCase(legacy=null,importId=null) {
  dialog(legacy?"Adopt existing case notes":"Create a case",form([
    paragraph(legacy?"The existing case.md and reports will be preserved. This adds structured case storage.":"Start with the question you want the evidence to answer.","muted"),
    field("Case ID","case_id","text",legacy?.id||"","Lowercase letters, numbers, dashes or underscores; up to 63 characters.",true),
    field("Title","title","text",legacy?.title||""),field("Case question","question","textarea","","Define the scope and the unresolved question.",true)
  ],legacy?"Adopt case":"Create case",async values=>{
    await action("create_case",{...values,adopt:!!legacy});
    if(importId)await action("assign_import",{import_id:importId,case_id:values.case_id});
    closeDialog();await bootstrap();await openCase(values.case_id.trim().toLowerCase());notice("Case ready. Add identifiers, import reports, or plan a scan.");
  }));
}
function editCase() {const c=state.data.case;dialog("Edit case",form([field("Title","title","text",c.title,"",true),field("Case question","question","textarea",c.question,"",true),selectField("Status","status",["open","closed"],c.status)],"Save case",async v=>{await action("update_case",caseArgs(v));closeDialog();await refresh();notice("Case updated.");}));}
async function exportCase() {const result=await action("export",caseArgs({}));dialog("Profile exported",el("div",{class:"stack"},paragraph("Read-only Markdown, JSON and HTML snapshots were written to this case’s exports folder."),el("pre",{},JSON.stringify(result,null,2)),paragraph("Original evidence files remain in case storage. These paths can also be opened from the terminal.","muted")));}
function renderHome(main) {
  const unassigned=state.inbox.filter(i=>i.state==="unassigned").length;
  main.append(el("div",{class:"page-heading"},el("div",{},el("div",{class:"eyebrow"},"YOUR INVESTIGATION WORKSPACE"),el("h1",{},"Bring the evidence together."),paragraph("Open a case, collect a new lead, or sort reports that arrived before the question.","muted")),button("Import files",()=>showImport(),"primary")));
  main.append(el("div",{class:"metrics"},metric("Cases",state.cases.length,"Your local case folders"),metric("Unassigned imports",unassigned,"Ready to organize")));
  const list=state.cases.length?el("div",{class:"stack"},state.cases.map(c=>el("article",{class:"item"},el("div",{class:"card-head"},el("h3",{},c.title),badge(c.status)),paragraph(c.question,"muted"),button(c.legacy?"Adopt existing notes":"Open case",()=>c.legacy?newCase(c):openCase(c.id))))):empty("No cases yet. Create one with a question, or import a report first.");
  main.append(card("Cases",list,button("New case",()=>newCase())),card("Imports inbox",inboxList(),button("Import files",()=>showImport())),paragraph("To discover reports already under OSINT, use the terminal’s discover command or select those files in the import picker.","muted"));
}
function metric(label,value,hint) {return el("div",{class:"card metric"},el("span",{class:"muted"},label),el("strong",{},value),el("small",{},hint));}
function renderOverview(main) {
  const d=state.data, accepted=d.observations.filter(o=>o.review_status==="relevant").length;
  main.append(el("div",{class:"metrics"},metric("Relevant findings",accepted,"Reviewed scanner observations"),metric("Connections to review",d.counts.review,"Proposals awaiting your decision"),metric("Evidence files",d.artifacts.length,"Originals retained"),metric("Contradictions",d.counts.contradictions,"Connections with conflicting evidence")));
  const groups=d.groups.filter(g=>g.length>1);
  const grouped=groups.length?el("div",{},groups.map((g,i)=>el("div",{class:"item"},el("h3",{},"Persona group "+(i+1)),paragraph(g.map(entityLabel).join(" · ")),el("small",{},"Accepted same-entity connections as of "+d.as_of)))):empty("No grouped personas yet. Add known accounts, then declare or review their connections.");
  const notes=d.notes.length?el("div",{},d.notes.map(n=>el("article",{class:"item"},badge(n.kind,n.kind==="allegation"?"pending":""),el("small",{},"User-declared · "+fmtDate(n.added)),paragraph(n.text)))):empty("Record a working finding, question or allegation. Evidence and certainty can develop over time.");
  main.append(el("div",{class:"grid"},card("Current profile",grouped,button("Connect personas",()=>{state.tab="connections";render();})),card("Findings & working notes",notes,button("Add note",addNote))));
  main.append(card("Accounts, people & assets",entityTable(),button("Add entity",addEntity)));
  main.append(card("Next steps",el("div",{class:"actions"},button("Import evidence",()=>showImport()),button("Review scanner findings",()=>{state.tab="findings";render();}),button("Plan a scan",()=>{state.tab="activity";render();}))));
}
function addNote() {dialog("Add a case note",form([selectField("Type","kind",["note","finding","allegation","question"]),field("Text","text","textarea","","Notes remain user-declared; allegations are labeled separately.",true)],"Save note",async v=>{await action("add_note",caseArgs(v));closeDialog();await refresh();notice("Note saved.");}));}
function addEntity() {dialog("Add an account, person or asset",form([field("Label","label","text","","A readable name for this entity.",true),selectField("Kind","kind",["account","person","persona","group","server","email","phone","transaction","incident","other"]),field("Platform","platform","text","","For example, Telegram, Roblox or Discord."),field("Identifier","identifier","text","","Account ID, username or URL; leave blank to use the label.")],"Add entity",async v=>{await action("add_entity",caseArgs(v));closeDialog();await refresh();notice("Entity added as user-declared.");}));}
function entityTable() {return state.data.entities.length?table(["Entity","Identifier","Origin"],state.data.entities.map(e=>[el("div",{},e.label,el("small",{},e.platform||e.kind)),el("span",{class:"mono break"},e.identifier),badge(e.basis)])):empty("Add an entity manually or import a structured scanner report.");}
function renderFindings(main) {
  const filters=el("div",{class:"filters"},selectField("Review","review",[["unreviewed","Needs review"],["relevant","Relevant"],["excluded","Excluded"],["all","All"]]),selectField("Reported result","status",[["positive","Hits & metadata"],["all","All results"],["hit","Hit"],["metadata","Metadata"],["absent","Absent"],["error","Error"],["skipped","Skipped"],["unknown","Unknown"]]),field("Search","search","search","","Target, site or URL"));
  const content=el("div",{});
  const update=()=>{
    const review=filters.querySelector('[name="review"]').value,status=filters.querySelector('[name="status"]').value,q=filters.querySelector('[name="search"]').value.toLowerCase();
    const items=state.data.observations.filter(o=>(review==="all"||o.review_status===review)&&(status==="all"||(status==="positive"?["hit","metadata"].includes(o.status):o.status===status))&&`${o.query} ${o.site} ${o.url}`.toLowerCase().includes(q));
    content.replaceChildren(items.length?table(["Finding","Reported result","Review","Evidence / decision"],items.map(o=>[el("div",{},el("strong",{},o.site),el("small",{},o.query),el("small",{class:"break"},o.url||"No account URL reported")),el("div",{},badge(o.status,["error","unknown"].includes(o.status)?"pending":""),el("small",{},o.tool)),el("div",{},badge(o.review_status,o.review_status==="unreviewed"?"pending":""),el("small",{},o.review_reason)),button("Review finding",()=>observationDetail(o))])):empty("No findings match these filters. Import a report or broaden the filters."));
  };
  filters.addEventListener("input",update);main.append(card("Review scanner findings",el("div",{},paragraph("A reported hit is a lead. Review relevance separately from the scanner’s result; excluded findings remain recoverable.","muted"),filters,content)));update();
}
function observationDetail(o) {
  const sources=el("div",{class:"stack"},o.sources.map(s=>el("div",{},artifactLink(s.artifact_id,artifactName(s.artifact_id)),el("small",{class:"mono"}," · "+s.selector))));
  dialog(o.site+" · "+o.query,el("div",{class:"stack"},el("div",{},badge(o.status),badge(o.review_status)),paragraph(o.url||"No account URL reported.","break"),card("Source records",sources),el("details",{},el("summary",{},"Scanner details"),el("pre",{},JSON.stringify(o.extra,null,2))),form([selectField("Review decision","status",["relevant","excluded","unreviewed"],o.review_status),field("Reason","reason","textarea",o.review_reason,"Explain why this result belongs in the case or should be excluded.")],"Save decision",async v=>{await action("review_observation",caseArgs({fingerprint:o.fingerprint,...v}));closeDialog();await refresh();notice("Review saved. You can restore the result or undo this decision in Activity.");})));
}
const relationKinds=["same_entity","associated_with","owns","purchased","links_to","advertises","depicts"];
function addRelation() {
  if(state.data.entities.length<2){notice("Add at least two entities before declaring a connection.");return;}
  const options=state.data.entities.map(e=>[e.id,entityLabel(e.id)]);
  dialog("Declare a connection",form([paragraph("Same entity groups personas. Associated with connects separate entities. The declaration and its evidence remain distinct.","muted"),selectField("From","source",options),selectField("Relationship","kind",relationKinds,"associated_with"),selectField("To","target",options,options[1][0]),field("Reason / context","note","textarea"),el("div",{class:"grid"},field("Valid from","since","date","","Leave unknown dates blank."),field("Valid through","until","date"))],"Declare connection",async v=>{const r=await action("add_relation",caseArgs(v));await refresh();closeDialog();notice("Connection saved as user-declared. Attach evidence to support, contradict or explain it.");claimDetail(state.data.relations.find(x=>x.id===r.id));}));
}
function renderConnections(main) {
  const controls=el("div",{class:"filters"},selectField("Connection status","status",[["active","Accepted & proposed"],["accepted","Accepted"],["proposed","Proposed"],["rejected","Rejected"]]),selectField("Focus entity","focus",[["","All entities"],...state.data.entities.map(e=>[e.id,entityLabel(e.id)])]),selectField("Graph limit","limit",["12","24","40"],"24"));
  const graphArea=el("div",{}),list=el("div",{});
  const update=()=>{
    const status=controls.querySelector('[name="status"]').value,focus=controls.querySelector('[name="focus"]').value,limit=Number(controls.querySelector('[name="limit"]').value);
    const relations=state.data.relations.filter(r=>(status==="active"?r.status!=="rejected":r.status===status)&&(!focus||r.source===focus||r.target===focus));
    graphArea.replaceChildren(relations.length?graph(relations,limit):empty("No connections in this view. Declare a known link or import reports to generate proposals."));
    list.replaceChildren(relations.length?table(["From → to","Connection","Review / evidence","Details"],relations.map(r=>[el("div",{},entityLabel(r.source),el("small",{},"→ "+entityLabel(r.target))),el("div",{},pretty(r.kind),el("small",{},pretty(r.basis))),el("div",{},badge(r.status,r.status==="proposed"?"pending":""),r.has_contradiction?badge("Contradiction","error"):null,el("small",{},r.evidence.length+" evidence links · "+(r.active_at_date?"Current / undated":"Outside current date"))),button("Review connection",()=>claimDetail(r))])):null);
  };
  controls.addEventListener("change",update);
  main.append(card("Connections",el("div",{},paragraph("Inspect a connection’s evidence before accepting a shared identity. Ownership can change over time.","muted"),controls,graphArea,el("div",{class:"section"},el("h3",{},"Connection list · accessible alternative"),list)),button("Declare connection",addRelation)));update();
}
function graph(relations,limit) {
  const all=[...new Set(relations.flatMap(r=>[r.source,r.target]))],ids=all.slice(0,limit),edges=relations.filter(r=>ids.includes(r.source)&&ids.includes(r.target));
  const svg=document.createElementNS("http://www.w3.org/2000/svg","svg");svg.setAttribute("viewBox","0 0 900 480");svg.setAttribute("class","graph");svg.setAttribute("role","group");svg.setAttribute("aria-label",`Connection overview: ${ids.length} entities. Full relationship details are available in the table below.`);
  const points=new Map(ids.map((id,i)=>{const angle=i*2*Math.PI/ids.length-Math.PI/2;return[id,{x:450+330*Math.cos(angle),y:240+175*Math.sin(angle)}];}));
  function sv(tag,attrs,text="") {const n=document.createElementNS(svg.namespaceURI,tag);for(const[k,v]of Object.entries(attrs))n.setAttribute(k,v);n.textContent=text;return n;}
  for(const r of edges){const a=points.get(r.source),b=points.get(r.target);svg.append(sv("line",{x1:a.x,y1:a.y,x2:b.x,y2:b.y,class:r.status}));if(ids.length<=12)svg.append(sv("text",{x:(a.x+b.x)/2,y:(a.y+b.y)/2,"text-anchor":"middle",class:"edge-label"},pretty(r.kind)));}
  for(const id of ids){const p=points.get(id),node=sv("g",{class:"graph-node",role:"button",tabindex:"0","aria-label":"Show connections for "+entityLabel(id)});node.append(sv("circle",{cx:p.x,cy:p.y,r:15}),sv("text",{x:p.x,y:p.y+32,"text-anchor":"middle"},entityLabel(id).slice(0,30)));const show=()=>dialog(entityLabel(id),el("div",{class:"stack"},relations.filter(r=>r.source===id||r.target===id).map(r=>button(`${entityLabel(r.source)} → ${pretty(r.kind)} → ${entityLabel(r.target)}`,()=>claimDetail(r)))));node.addEventListener("click",show);node.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();show();}});svg.append(node);}
  return el("div",{},el("div",{class:"graph-scroll",tabindex:"0","aria-label":"Scrollable connections graph"},svg),paragraph(`Showing ${ids.length} of ${all.length} connected entities. Solid: accepted; dashed: proposed. Direction and dates are in the table. Scroll horizontally on narrow screens.`,"muted"));
}
function claimDetail(r) {
  if(!r)return;
  const evidence=r.evidence.length?el("div",{},r.evidence.map(e=>el("div",{class:"item"},badge(e.role,e.role==="contradicts"?"error":""),artifactLink(e.artifact_id,artifactName(e.artifact_id)),paragraph(e.note),el("p",{class:"mono break"},e.selector||"Whole artifact"),el("div",{class:"actions"},button("Inspect artifact",()=>inspectArtifact(e.artifact_id)),button("Remove evidence link",async()=>{await action("remove_evidence",caseArgs({evidence_id:e.id}));await refresh();claimDetail(state.data.relations.find(x=>x.id===r.id));},"danger"))))):empty("No supporting files yet. Attach an artifact and explain which part matters.");
  dialog("Connection claim",el("div",{class:"stack"},el("h3",{},entityLabel(r.source)+" → "+pretty(r.kind)+" → "+entityLabel(r.target)),el("div",{},badge(r.basis),badge(r.status,r.status==="proposed"?"pending":"")),paragraph(r.note||"No declaration note supplied."),paragraph(`Dates: ${r.since||"Unknown start"} → ${r.until||"Unknown end"}`,"muted"),card("Claim-level evidence",evidence,button("Attach evidence",()=>attachEvidence(r.id))),form([selectField("Decision","status",["accepted","proposed","rejected"],r.status),selectField("Relationship type","kind",relationKinds,r.kind),field("Decision reason","reason","textarea","","Accept, reclassify or retract this claim. Its original basis is preserved.")],"Save review",async v=>{await action("review_relation",caseArgs({relation_id:r.id,...v}));closeDialog();await refresh();notice("Connection reviewed. Latest review decisions can be undone in Activity.");})));
}
function attachEvidence(relationId) {
  if(!state.data.artifacts.length){dialog("Import evidence first",el("div",{class:"stack"},paragraph("This case has no evidence files. Import a screenshot, document or report, then return to this claim."),button("Import files",()=>showImport(),"primary")));return;}
  const preview=el("div",{}),selectorField=field("Locator / excerpt","selector","textarea","","Record a page, message ID, report selector, quote or screenshot region."),selectorInput=selectorField.querySelector("textarea");
  const f=form([selectField("Evidence file","artifact_id",state.data.artifacts.map(a=>[a.id,a.name])),selectField("Evidence role","role",["supports","contradicts","context"]),preview,selectorField,field("Explanation","note","textarea","","Explain how this evidence bears on this particular connection.")],"Attach to claim",async v=>{await action("attach_evidence",caseArgs({relation_id:relationId,...v}));await refresh();claimDetail(state.data.relations.find(x=>x.id===relationId));notice("Evidence linked to the claim.");});
  const select=f.querySelector('[name="artifact_id"]');
  const update=()=>{const a=state.data.artifacts.find(x=>x.id===select.value);preview.replaceChildren(raster(a.name)?imagePreview(a,selectorInput):paragraph("This file is available as an inert download. Add a text locator above.","muted"),artifactLink(a.id));};
  select.addEventListener("change",update);update();dialog("Attach evidence to this claim",f);
}
const raster=name=>/\.(png|jpe?g|gif|webp)$/i.test(name);
function imagePreview(artifact,locator=null) {
  const image=el("img",{src:artifactUrl(artifact.id,true),alt:"Evidence preview: "+artifact.name,draggable:"false"}),overlay=el("div",{class:"image-selection",hidden:true}),stage=el("div",{class:"image-stage"},image,overlay),message=paragraph(locator?"Drag over the screenshot to record a rectangle, or enter a locator using the keyboard.":"Raster preview of the preserved original.","muted");
  image.addEventListener("error",()=>{message.textContent="Preview unavailable. Download the original to inspect it in an appropriate viewer.";stage.hidden=true;});
  if(locator){let start=null;const point=e=>{const r=image.getBoundingClientRect();return{x:Math.max(0,Math.min(r.width,e.clientX-r.left)),y:Math.max(0,Math.min(r.height,e.clientY-r.top)),r};};
    stage.addEventListener("pointerdown",e=>{if(!image.complete||!image.naturalWidth)return;start=point(e);stage.setPointerCapture(e.pointerId);overlay.hidden=false;overlay.style.left=start.x+"px";overlay.style.top=start.y+"px";overlay.style.width="0px";overlay.style.height="0px";});
    stage.addEventListener("pointermove",e=>{if(!start)return;const p=point(e);overlay.style.left=Math.min(start.x,p.x)+"px";overlay.style.top=Math.min(start.y,p.y)+"px";overlay.style.width=Math.abs(p.x-start.x)+"px";overlay.style.height=Math.abs(p.y-start.y)+"px";});
    stage.addEventListener("pointerup",e=>{if(!start)return;const p=point(e),sx=image.naturalWidth/p.r.width,sy=image.naturalHeight/p.r.height;locator.value=`rectangle: x=${Math.round(Math.min(start.x,p.x)*sx)}, y=${Math.round(Math.min(start.y,p.y)*sy)}, width=${Math.round(Math.abs(p.x-start.x)*sx)}, height=${Math.round(Math.abs(p.y-start.y)*sy)}; image=${image.naturalWidth}x${image.naturalHeight}`;start=null;});stage.addEventListener("pointercancel",()=>{start=null;});}
  return el("div",{class:"stack"},stage,message);
}
function inspectArtifact(id) {const a=state.data.artifacts.find(x=>x.id===id);dialog(a.name,el("div",{class:"stack"},raster(a.name)?imagePreview(a):paragraph("This report is downloaded as a file; active report content is never embedded in the editor."),artifactLink(id),el("details",{},el("summary",{},"Origin, parser & integrity record"),el("pre",{},JSON.stringify(a,null,2))),paragraph("The stored hash checks whether file bytes changed. It does not establish source authenticity.","muted")));}
function renderEvidence(main) {
  main.append(card("Evidence library",state.data.artifacts.length?table(["Artifact","Parser / source","Inspect"],state.data.artifacts.map(a=>[el("div",{},a.name,el("small",{},fmtDate(a.added))),el("div",{},badge(a.adapter),el("small",{class:"break"},a.metadata.origin||"File upload"),el("small",{},(a.metadata.issues||[]).join(" · "))),button("Inspect evidence",()=>inspectArtifact(a.id))])):empty("Import a scanner report or supporting file. Originals are preserved alongside structured findings."),button("Import files",()=>showImport(),"primary")));
  main.append(card("Imports inbox",inboxList()));
}
function inboxList() {
  if(!state.inbox.length)return empty("No imports yet. Files can remain unassigned until you’re ready to open a case.");
  return el("div",{},state.inbox.map(item=>el("article",{class:"item"},el("div",{class:"card-head"},el("h3",{},item.name),badge(item.state,item.state==="unassigned"?"pending":"")),paragraph(`${pretty(item.preview.adapter)} · ${(item.preview.targets||[]).length} targets · ${fmtDate(item.added)}`,"muted"),item.assignments.length?paragraph("Assigned to: "+[...new Set(item.assignments.map(a=>a.case_id))].join(", "),"muted"):null,el("div",{class:"actions"},button("Preview / assign",()=>assignImport(item)),button("Create case from import",()=>newCase(null,item.id))))));
}
function targetSelection(targets=[]) {return targets.length?el("fieldset",{},el("legend",{},"Targets to include"),targets.map(target=>{const id="target-"+(++fieldNumber);return el("label",{class:"check",for:id},el("input",{id,type:"checkbox",name:"targets",value:target,checked:true}),target);})):null;}
function targetsFrom(formNode,preview) {return (preview.targets||[]).length?[...formNode.querySelectorAll('[name="targets"]:checked')].map(x=>x.value):undefined;}
function previewDetails(p) {return el("div",{class:"stack"},el("div",{},badge(p.adapter||"attachment"),el("small",{},p.bytes?`${p.bytes.toLocaleString()} bytes`:"Preserved original")),paragraph(Object.entries(p.counts||{}).map(([k,v])=>`${v} ${pretty(k)}`).join(" · ")||"No structured observations. Available as supporting evidence.","muted"),(p.issues||[]).length?el("div",{},el("h3",{},"Parser notes"),el("ul",{},p.issues.map(issue=>el("li",{},issue)))):null);}
function assignImport(item) {
  const options=state.cases.filter(c=>!c.legacy).map(c=>[c.id,c.title]);
  if(!options.length){newCase(null,item.id);return;}
  dialog("Assign import · "+item.name,form([previewDetails(item.preview),selectField("Destination case","case_id",options,state.caseId||options[0][0]),targetSelection(item.preview.targets)],"Assign selected results",async(v,f)=>{const targets=targetsFrom(f,item.preview);if(targets&&!targets.length)throw new Error("Select at least one target.");const r=await action("assign_import",{import_id:item.id,case_id:v.case_id,...(targets?{targets}:{})});closeDialog();await bootstrap();await openCase(v.case_id,"evidence");notice(`Import assigned. ${r.added_observations} new source observations added; existing decisions were preserved.`);}));
}
function showImport() {
  const input=el("input",{id:"import-file",type:"file",multiple:true}),zone=el("div",{class:"dropzone"},el("label",{for:"import-file",class:"field-label"},"Choose reports, screenshots or documents"),paragraph("Drop files here, or choose files. Maximum 32 MiB each. Previewing does not save them.","muted"),input),queue=el("div",{class:"stack"}),progress=el("p",{role:"status",class:"muted"});
  const draw=()=>{queue.replaceChildren(...state.uploads.map((u,index)=>card(u.filename,form([previewDetails(u.preview),selectField("Destination","case_id",[["","Leave unassigned in inbox"],...state.cases.filter(c=>!c.legacy).map(c=>[c.id,c.title])],state.caseId),targetSelection(u.preview.targets)],"Import this file",async(v,f)=>{const targets=targetsFrom(f,u.preview);if(targets&&!targets.length)throw new Error("Select at least one target.");const result=await action("import_upload",{filename:u.filename,data:u.data,...(v.case_id?{case_id:v.case_id}:{}),...(targets?{targets}:{})});state.uploads=state.uploads.filter(x=>x!==u);await refresh();draw();notice(result.assignment?`Imported ${u.filename}: ${result.assignment.added_observations} new source observations.`:`${u.filename} saved to the unassigned inbox.`);}),button("Discard preview",()=>{state.uploads.splice(index,1);draw();}))));};
  const load=async files=>{input.disabled=true;for(const file of files){try {if(file.size>32*1024*1024)throw new Error(file.name+" exceeds the 32 MiB limit.");progress.textContent="Previewing "+file.name+"…";const data=await new Promise((resolve,reject)=>{const r=new FileReader();r.onload=()=>resolve(String(r.result).split(",")[1]);r.onerror=()=>reject(new Error("Unable to read "+file.name));r.readAsDataURL(file);});const preview=await action("preview_upload",{filename:file.name,data});state.uploads.push({filename:file.name,data,preview});draw();}catch(e){progress.textContent=e.message;notice(e.message,true);}}input.disabled=false;input.value="";progress.textContent=state.uploads.length+" file preview(s) ready. Import each explicitly.";};
  input.addEventListener("change",()=>run(()=>load([...input.files])));zone.addEventListener("dragover",e=>{e.preventDefault();zone.classList.add("drag");});zone.addEventListener("dragleave",()=>zone.classList.remove("drag"));zone.addEventListener("drop",e=>{e.preventDefault();zone.classList.remove("drag");run(()=>load([...e.dataTransfer.files]));});draw();dialog("Import existing results & evidence",el("div",{class:"stack"},zone,progress,queue));
}
function renderActivity(main) {
  main.append(card("Open scanner",form([
    paragraph("Use the scanner’s full interactive terminal menu. This session stays attached to this case; each scan saves and imports its own reports. Opening a menu does not authorize a scan.","muted"),
    selectField("Interactive scanner","tool",[["maigret","Maigret"],["scanner","User Scanner"],["phone","Phone Lookup"]]),
    selectField("Terminal placement","mode",[["auto","Split pane when available"],["tab","New terminal tab"]])
  ],"Open interactive scanner",async v=>{const result=await withAuthorization(()=>action("open_scanner",caseArgs(v)));if(!result)return;await refresh();notice(`Scanner session ${result.state||"opened"} in ${result.mode}. Complete scans in that terminal; refresh this case to see imported findings.`);} )));
  main.append(el("details",{class:"section"},el("summary",{},"Quick scan · profiler presets"),card("Plan a quick scan",scanForm())));
  const jobs=state.data.jobs.length?table(["Run","State","Started","Controls"],state.data.jobs.map(j=>[el("div",{},pretty(j.tool),el("small",{},j.target),j.plan.mode?badge(j.plan.mode):null),el("div",{},badge(j.state,["running","partial","launching"].includes(j.state)?"pending":j.state==="failed"?"error":""),el("small",{},j.message)),fmtDate(j.started),el("div",{class:"actions"},j.plan.mode!=="interactive_session"?button("View log",()=>showLog(j)):null,j.state==="running"?(j.plan.mode?paragraph("Use the scanner terminal to interrupt or exit.","muted"):button("Cancel scan",()=>cancelScan(j),"danger")):null)])):empty("No scans run for this case. Open a scanner or review a Quick scan plan.");
  main.append(card("Scan history",jobs,button("Refresh runs",refresh)));
  const seen=new Set();
  const events=state.data.events.map(e=>{
    const latest=!seen.has(e.subject);seen.add(e.subject);
    const heading=el("div",{class:"card-head"},el("strong",{},pretty(e.action)),el("small",{},fmtDate(e.added)));
    const detail=el("details",{},el("summary",{},"View recorded change"),el("pre",{},JSON.stringify({subject:e.subject,before:e.before,after:e.after},null,2)));
    const undo=latest&&["review_observation","review_relation"].includes(e.action)?button("Undo decision",async()=>{await action("undo",caseArgs({event_id:e.id}));await refresh();notice("Latest decision undone.");}):null;
    return el("article",{class:"item"},heading,detail,undo);
  });
  main.append(card("Decision & activity history",events.length?el("div",{},events):empty("Case activity will appear here.")));
}
function scanForm() {
  const f=form([paragraph("Choose a tool and identifier. Review the collection scope before starting; creating a plan makes no external requests.","muted"),el("div",{class:"grid"},selectField("Scanner","tool",[["maigret","Maigret"],["scanner","User Scanner"],["phone","Phone Lookup"]]),selectField("Identifier type","kind",["username","email","phone"])),field("Target identifier","target","text","","One identifier per run.",true),el("div",{class:"grid"},field("Maigret top sites","top","number","500","1–10,000; recursion disabled."),field("Phone region","region","text","","Optional two-letter country code.")),field("Scanner modules","modules","text","","Optional comma-separated names; defaults follow the reviewed scanner configuration.")],"Review scan plan",async v=>{
    const plan=await action("plan_scan",caseArgs({...v,top:Number(v.top)||500}));
    dialog("Review collection plan",form([paragraph(plan.notice),el("pre",{},JSON.stringify(Object.fromEntries(Object.entries(plan).filter(([k])=>k!=="plan_id")),null,2)),field("Type RUN to authorize this scan","confirm","text","","This sends the identifier to the selected sites/providers. Reports will be attached to this case.",true)],"Start this scan",async values=>{if(values.confirm!=="RUN")throw new Error("Type RUN exactly to confirm this plan.");const result=await withAuthorization(()=>action("start_scan",{plan_id:plan.plan_id,confirm:values.confirm}));if(!result)return;closeDialog();await refresh();notice("Scan started: "+result.job_id+". Use Refresh runs to check progress.");}));
  });
  f.querySelector('[name="top"]').min="1";f.querySelector('[name="top"]').max="10000";
  f.querySelector('[name="tool"]').addEventListener("change",e=>{f.querySelector('[name="kind"]').value=e.target.value==="phone"?"phone":"username";});return f;
}
async function showLog(job) {const log=await action("job_log",caseArgs({job_id:job.id}));dialog("Scan log · "+job.tool,el("div",{class:"stack"},paragraph(job.target+" · "+job.state),el("pre",{tabindex:"0"},log.text||"No log output yet."),button("Refresh log",()=>showLog(job))));}
function cancelScan(job) {dialog("Cancel this scan?",el("div",{class:"stack"},paragraph(`Stop ${job.tool} collection for ${job.target}? Files already collected will remain available.`),button("Cancel scan",async()=>{await action("cancel_scan",{job_id:job.id});closeDialog();await refresh();notice("Cancellation requested. Refresh runs to see the final outcome.");},"danger")));}
$("dialog-close").addEventListener("click",closeDialog);
$("dialog").addEventListener("close",()=>{if(document.activeElement===document.body)$("main").focus({preventScroll:true});});
$("new-button").addEventListener("click",()=>newCase());
$("home-button").addEventListener("click",()=>run(()=>openCase("")));
$("refresh-button").addEventListener("click",()=>run(refresh));
$("case-picker").addEventListener("change",e=>run(()=>openCase(e.target.value)));
$("help-button").addEventListener("click",()=>dialog("One case store, two workspaces",el("div",{class:"stack"},paragraph("The terminal and browser read the same case database. Refresh after making changes in the other interface."),el("pre",{},"osint-case\nosint-case new\nosint-case open <case-id>\nosint-case scan <case-id>\nosint-case ui <case-id>"),paragraph("Original files are retained under OSINT. Imports never trigger scans or model calls. Same-entity declarations group personas; association alone does not combine identities."))));
run(async()=>{try {const session=await request("/api/session");state.token=session.token;await bootstrap();const id=new URLSearchParams(location.search).get("case");if(id)await openCase(id);else render();} catch(error) {$("main").replaceChildren(empty("The workspace could not load. Check the local server, then use Refresh to retry or Cases & imports to return home."));throw error;}});
