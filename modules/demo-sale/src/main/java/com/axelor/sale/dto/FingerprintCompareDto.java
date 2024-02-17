package com.axelor.sale.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FingerprintCompareDto {
    private String code;
    private FingerprintDto fingerprint;
}
