package com.secretdrop.secret;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("local")
class SecretControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SecretRepository secretRepository;

    @BeforeEach
    void clean() {
        secretRepository.deleteAll();
    }

    @Test
    void createRevealAndSecondRevealReturns404() throws Exception {
        MvcResult createResult = mockMvc.perform(post("/api/secrets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"content":"integration-secret","maxViews":1}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.accessToken").isNotEmpty())
                .andReturn();

        String token = objectMapper.readTree(createResult.getResponse().getContentAsString())
                .path("data").path("accessToken").asText();

        mockMvc.perform(get("/api/secrets/{token}/reveal", token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.content").value("integration-secret"));

        mockMvc.perform(get("/api/secrets/{token}/reveal", token))
                .andExpect(status().isNotFound());
    }

    @Test
    void concurrencyOnlyAllowsSingleRevealForOneViewSecret() throws Exception {
        MvcResult createResult = mockMvc.perform(post("/api/secrets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"content":"race","maxViews":1}
                                """))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode data = objectMapper.readTree(createResult.getResponse().getContentAsString()).path("data");
        String token = data.path("accessToken").asText();

        ExecutorService pool = Executors.newFixedThreadPool(8);
        List<Callable<Integer>> tasks = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            tasks.add(() -> mockMvc.perform(get("/api/secrets/{token}/reveal", token))
                    .andReturn()
                    .getResponse()
                    .getStatus());
        }

        List<Future<Integer>> results = pool.invokeAll(tasks);
        pool.shutdown();

        long successCount = results.stream()
                .mapToInt(f -> {
                    try {
                        return f.get();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .filter(status -> status == 200)
                .count();

        assertThat(successCount).isEqualTo(1);
    }
}