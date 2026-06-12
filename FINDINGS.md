# FINDINGS.md — Evidence-Driven Remediation Engine


## 1. Which similarity function did you choose for Layer 2, and why? *(Bạn chọn hàm độ tương đồng nào cho Layer 2, và tại sao?)*

Tôi chọn một **độ tương đồng lai có trọng số (weighted hybrid similarity)** kết
hợp ba thành phần, cộng thêm một hình phạt về tính nhất quán (coherence penalty):

| Thành phần | Trọng số | Phương pháp |
|-----------|--------|--------|
| Log similarity | 0.40 | Độ phủ có trọng số IDF của các log signature lịch sử tìm thấy (dưới dạng substring) trong các message thô của incident hiện tại |
| Trace similarity | 0.35 | Điểm khớp cạnh (edge-match): khớp các cạnh trace lịch sử với các cạnh bất thường hiện tại theo cặp `(from,to)`, chấm điểm theo độ gần của error-rate |
| Service overlap | 0.25 | Chỉ số Jaccard trên tập service bị ảnh hưởng |

**Lựa chọn thiết kế then chốt — khớp log có trọng số IDF.** Những signature
chung chung như `"degraded behavior detected"` xuất hiện trong **15/29** mục
lịch sử (IDF = ln(29/15)+1 ≈ **1.66**), trong khi những signature đặc thù như
`"ConnectionPool: timeout acquiring connection"` chỉ xuất hiện ở **3/29**
(IDF ≈ **3.27**). Nếu không có trọng số IDF, các signature chung chung sẽ khiến
mọi incident trông giống một nửa corpus. (Cả hai con số đã được kiểm chứng lại
với `incidents_history.json`, n=29.)

**Phương án đã cân nhắc — Cosine similarity trên vector TF-IDF.** Tôi đã cân
nhắc mã hóa cả incident hiện tại lẫn incident lịch sử thành vector TF-IDF trên
các log template đã chuẩn hóa rồi tính khoảng cách cosine. Tôi loại bỏ nó vì:
1. Corpus chỉ có 29 mục — quá ít để xây một bộ từ vựng có ý nghĩa; vector
   TF-IDF nhiều chiều sẽ overfit với số neighbour ít ỏi như vậy.
2. Khớp substring (substring containment) tận dụng trực tiếp việc
   `log_signatures` lịch sử là *template đã làm sạch* còn log hiện tại là
   *message thô*. Cosine sẽ đòi hỏi quy cả hai về cùng một biểu diễn trước,
   thêm một bước dễ vỡ.

**Kiểm chứng thực nghiệm.** Trên **E01** (pool exhaustion), độ tương đồng lai
xếp `INC-2025-11-08` (connection_pool_exhaustion, success) ở vị trí đầu với
**sim = 0.641**, bỏ xa các neighbour tiếp theo chỉ còn **0.247**
(`INC-2025-09-05` / `INC-2026-05-10`, cùng class) và **0.158**
(`INC-2025-07-04`, lock_contention — một class *khác*). Một độ tương đồng chỉ
dựa trên log sẽ không tách E01 khỏi E06 sạch sẽ như vậy, vì log của E06 *cũng*
chứa các dòng pool-exhaustion.

**Hình phạt coherence.** Khi incident hiện tại có một bất thường trace nổi trội
mạnh (`error_rate > 0.15`) nhưng các trace signature của một mục lịch sử lại
không khớp với cạnh nổi trội đó, độ tương đồng bị nhân **×0.55**. Đây chính là
cách xử lý **E06**: bất thường nổi trội của incident là `cart-svc → cart-redis`
(`error_rate = 0.21`, `p99_deviation_ratio = 5.96`), nhưng các mục lịch sử
`connection_pool_exhaustion` có log khớp cao lại đều mô tả cạnh
`checkout → payment`, nên bị phạt — độ tương đồng của chúng tụt xuống
**0.38 / 0.36** thay vì áp đảo chỉ nhờ khớp log.

---

## 2. How does outcome-weighted voting change the candidate ranking versus a pure-similarity ranking? *(Bỏ phiếu có trọng số theo kết quả làm thay đổi xếp hạng ứng viên thế nào so với xếp hạng thuần theo độ tương đồng?)*

**Trọng số theo kết quả:** `success = 1.0`, `partial = 0.40`, `failed = 0.05`.
**Trọng số phiếu:** `vote_weight = similarity² × outcome_weight`
(`similarity²` khuếch đại match đứng đầu và triệt tiêu các neighbour ở xa).

**Ví dụ cụ thể — E01, nơi việc đánh trọng số theo kết quả làm *đảo* action được chọn để ship.**

Các neighbour bỏ phiếu của E01 (sim ≥ 0.10) và action mà mỗi neighbour đóng góp:

| Neighbour | sim | outcome | action đóng góp |
|-----------|-----|---------|---------------------|
| INC-2025-11-08 | 0.641 | success | rollback_service, increase_pool_size |
| INC-2025-09-05 | 0.247 | success | rollback_service, increase_pool_size |
| INC-2026-05-10 | 0.247 | **partial** | rollback_service *(chỉ mỗi cái này)* |
| INC-2025-07-04 | 0.158 | success | restart_pod |
| INC-2026-02-22 | 0.140 | success | page_oncall |

Khác biệt duy nhất giữa `rollback_service` và `increase_pool_size` là neighbour
**kết quả partial** `INC-2026-05-10`, vốn chỉ dùng rollback *một mình* và chỉ
giải quyết được incident một phần.

| Action | Phiếu thô thuần-tương-đồng (Σ sim²) | Phiếu thô có trọng số kết quả (Σ sim²·w) |
|--------|-----------------------------------|--------------------------------------|
| `rollback_service` | 0.4105 + 0.0611 + 0.0611 = **0.533** | 0.4105 + 0.0611 + (0.0611×0.4) = **0.496** |
| `increase_pool_size` | 0.4105 + 0.0611 = **0.472** | 0.4105 + 0.0611 = **0.472** |

Việc chiết khấu phiếu partial thu hẹp khoảng cách dẫn trước của rollback so với
increase từ **0.061** (thuần) xuống **0.024** (có trọng số). Sự thu hẹp này trở
nên quyết định khi Layer 3 áp chi phí vào:

- **Thuần-tương-đồng** → confidence `rollback 0.508 / increase 0.450` →
  EU `rollback 0.459` so với `increase 0.435` → **rollback được ship**.
- **Có trọng số kết quả** → confidence `rollback 0.490 / increase 0.466` →
  EU `increase 0.451` so với `rollback 0.443` → **increase_pool_size được ship**.

Vậy việc đánh trọng số theo kết quả làm nhiều hơn là chỉ chấm lại điểm: bằng
cách chiết khấu phiếu rollback partial đơn lẻ đó, nó cho phép `increase_pool_size`
**rẻ hơn** (cost 1, downtime 0) vượt qua `rollback_service` đắt hơn (cost 10,
downtime 2) về expected utility. Cả hai đều là action được chấp nhận cho E01,
nên quyết định vẫn đúng — nhưng action mà engine thực sự ship thì đã thay đổi.

---

## 3. For one eval incident, explain the EV calculation in full *(Với một incident trong tập eval, giải thích đầy đủ phép tính EV.)*

**E01 — connection pool exhaustion → ship `increase_pool_size`.**

### Tập ứng viên từ Layer 2 (confidence có trọng số kết quả)

| Action | Confidence | Điểm thô |
|--------|-----------|-----------|
| `rollback_service`   | 0.4901 | 0.496 |
| `increase_pool_size` | 0.4660 | 0.472 |
| `restart_pod`        | 0.0246 | 0.025 |
| `page_oncall`        | 0.0194 | 0.020 |

### Công thức EU: `EU = confidence × (1 − cost_penalty / 3)`

trong đó `cost_penalty = 0.30·(cost/20) + 0.30·(downtime/10) + 0.40·(blast/5)`,
và `page_oncall` dùng một chi phí cơ hội cố định là `0.35`.

| Action | Confidence | cost_penalty | EU | Cổng blast |
|--------|-----------|-------------|-----|-----------|
| `increase_pool_size` | 0.466 | 0.095 | 0.466 × (1 − 0.0317) = **0.4512** | PASS (blast=1) |
| `rollback_service`   | 0.490 | 0.290 | 0.490 × (1 − 0.0967) = **0.4427** | PASS (blast=1) |
| `page_oncall`        | 0.019 | 0.350 | 0.019 × (1 − 0.1167) = **0.0171** | PASS (blast=0) |
| `restart_pod`        | 0.025 | —      | — | **BỊ LOẠI** (conf 0.02 < 0.25, blast=1) |

**cost_penalty của `rollback_service`:** cost 10/20 = 0.50, downtime 2/10 = 0.20,
blast 1/5 = 0.20 → 0.30·0.50 + 0.30·0.20 + 0.40·0.20 = 0.15 + 0.06 + 0.08 = **0.29**.
**cost_penalty của `increase_pool_size`:** cost 1/20 = 0.05, downtime 0,
blast 1/5 = 0.20 → 0.30·0.05 + 0.40·0.20 = 0.015 + 0.08 = **0.095**.

**Người thắng:** `increase_pool_size` với **EU = 0.4512**, hơn
`rollback_service` (EU = 0.4427) đúng **0.0085**. Khoảng cách sít sao này phản
ánh đúng thiết kế: confidence là tín hiệu chủ đạo, cost chỉ là yếu tố phá hòa ở
mức vừa phải. `rollback` có confidence nhỉnh hơn một chút nhưng cost_penalty cao
hơn hẳn (0.29 so với 0.095), nên action rẻ hơn thắng.

**page_oncall:** dù chi phí hạ tầng bằng 0, chi phí cơ hội được tiêm vào
(0.35, đại diện cho ~30 phút MTTR của con người) cộng với confidence rất nhỏ
(0.019) khiến nó chỉ đạt EU = 0.017 — đúng đắn là không bao giờ cạnh tranh được
trên một incident đã hiểu rõ.

---

## 4. When did your engine choose to escalate (page_oncall) instead of auto-act? *(Khi nào engine chọn leo thang (page_oncall) thay vì tự hành động?)*

Engine của tôi leo thang trên **6/8** incident eval. Quan trọng là: việc leo
thang phát sinh từ **ba cơ chế khác biệt**, không phải một — và chỉ hai trong
sáu trường hợp là OOD thực sự:

| Incident | conf | max_sim | Vì sao leo thang | Đúng? |
|----------|------|---------|------------------|----------|
| **E02** | 0.698 | 0.488 | **Lịch sử bảo page.** Match đầu bảng `INC-2025-08-17` (tls_expiry, success) bản thân nó được giải bằng `page_oncall`, nên page gom hết phiếu; mọi auto-action rớt xuống dưới cổng blast 0.25. | TLS rotation là việc cert-ops, chỉ con người làm được |
| **E04** | 0.136 | 0.136 | **OOD.** `max_similarity 0.136 < 0.25` → buộc leo thang. | đáp án chấp nhận page (hoặc dns_config_rollback) |
| **E05** | 0.008 | 0.602 | **Xung đột + cổng blast.** Không phải OOD, nhưng top-4 trộn `connection_pool_exhaustion` với `lock_contention` (`INC-2025-07-04`, sim 0.586) → conflict dampening ×0.55 kéo mọi auto-action xuống dưới 0.25 → chỉ page sống sót qua cổng. | đáp án chấp nhận page (hoặc rollback:payment-svc) |
| **E06** | 0.083 | 0.377 | **Xung đột + coherence penalty + cổng blast.** Log nói payment-svc (pool exhaustion); trace nổi trội nói `cart-svc → cart-redis`. Coherence penalty + conflict dampening kéo các action pool-exhaustion xuống dưới cổng. | đáp án chấp nhận page (hoặc restart:cart-svc) |
| **E07** | 1.000 | 0.426 | **Lịch sử bảo page.** Match đầu bảng `INC-2025-10-15` (infinite_retry, success) được giải bằng `page_oncall`; nó là ứng viên duy nhất. *(Không phải OOD — sim 0.426 cao hơn ngưỡng.)* | đáp án chỉ chấp nhận page |
| **E08** | 0.052 | 0.052 | **OOD.** `max_similarity 0.052 < 0.25`, không có ứng viên nào → buộc leo thang. | đáp án chấp nhận page (hoặc rollback:t24-service) |

Cả sáu quyết định leo thang đều đúng so với ground truth của eval.

**Nơi leo thang được né đúng đắn:** **E01** (pool exhaustion rõ ràng,
conf 0.466 → `increase_pool_size`) và **E03** (memory leak rõ ràng, conf 0.987 →
`rollback_service`). Cả hai đều mang `must_not_action: page_oncall`, nên nếu leo
thang sẽ bị trừ điểm — engine tự hành động trên cả hai.

**Ghi chú thiết kế đáng nêu:** chỉ **E04** và **E08** kích hoạt đường OOD tường
minh. E05/E06 leo thang vì cổng blast-radius (và conflict dampening) loại mọi
auto-action, còn E02/E07 leo thang vì incident lịch sử được match *bản thân nó*
đã được giải bằng cách page. Đây là hành vi mong muốn — engine đi tới "page" qua
bằng chứng, chứ không phải mặc định mù quáng — nhưng điều đó nghĩa là "leo thang"
trong engine này không đồng nghĩa với "input mới lạ".

---

## 5. What is the most likely class of incident that breaks your engine? *(Lớp incident nào nhiều khả năng làm hỏng engine của bạn nhất?)*

**Lớp: incident có *mẫu lỗi đã biết* nhưng *topology service mới lạ*.**

**E08 minh họa điều này.** Đó là một cascade 4 service trong đó gốc thật là leaf
sâu nhất (`t24-service`), nhưng các service (`t24-service`, `bb-edge`,
`datapower`) chưa từng xuất hiện trong corpus lịch sử. Engine của tôi chấm nó
ở `max_similarity = 0.052` và leo thang qua đường OOD. Như vậy là *chấp nhận
được* (page là một action được chấp nhận), nhưng không *lý tưởng*: một engine
thông minh hơn sẽ nhận ra *hình dạng* — cascade từ leaf sâu lên edge phát alert —
ngay cả khi tên service khác nhau, và có thể đề xuất `rollback_service:t24-service`
(cũng được chấp nhận).

**Kịch bản thất bại cụ thể.** Một sự cố connection-pool exhaustion trên
`inventory-svc` sẽ khớp các log signature pool-exhaustion, nhưng mọi mục
pool-exhaustion lịch sử đều nhắm vào `payment-svc`. Thành phần log (trọng số
0.40) sẽ kích hoạt, nhưng thành phần trace (0.35, edge-match) và service Jaccard
(0.25) sẽ cùng sụp đổ vì không cạnh lịch sử nào nhắc tới `inventory-svc`. Độ
tương đồng sẽ rơi vào dải 0.10–0.20 — ngay sát ranh giới OOD 0.25 — và engine có
thể đánh giá thấp một incident thực ra đã biết.

**Cải tiến đề xuất nhưng tôi chưa triển khai — chuẩn hóa theo vai trò service
(service-role normalisation).** Thay vì khớp tên service theo nghĩa đen (Jaccard
trên `affected_services` và edge-match chính xác trong trace similarity), hãy ánh
xạ mỗi service về *vai trò* của nó trong topology (ví dụ "api-tier caller",
"datastore backend", "edge proxy") rồi tính độ tương đồng trên vai trò. Khi đó
`inventory-svc → catalog-db` sẽ khớp với `payment-svc → payments-db` vì cả hai
đều là "api → store". Tôi chưa triển khai vì:
1. Corpus nhỏ (29 mục) — khớp theo vai trò có nguy cơ tổng quát hóa quá đà và
   cần một tập kiểm chứng lớn hơn để tinh chỉnh an toàn.
2. Cách tiếp cận hiện tại đã đạt **8/8 được chấp nhận, 0 forbidden** trên tập
   eval; giá trị biên của role normalisation không kiểm chứng được nếu không có
   thêm incident thử nghiệm.
3. Ngân sách thời gian: trích vai trò từ topology và đấu lại cả ba thành phần
   tương đồng (cộng với cả phần kiểm tra coherence) là một cuộc tái cấu trúc
   không nhỏ ở cả feature layer lẫn retrieval layer.
