<template>
  <span>
    <v-alert
      :value="success"
      dismissible
      color="success"
      border="left"
      elevation="2"
      colored-border
      transition="scale-transition"
      icon="mdi-check"
    >
      <a :href="link" target="_blank" rel="noopener">{{ link }}</a> {{ successMsg }}
    </v-alert>

    <v-alert
      :value="error"
      dismissible
      color="error"
      border="left"
      elevation="2"
      colored-border
      transition="scale-transition"
      icon="mdi-alert-outline"
    >
      <a :href="link" target="_blank" rel="noopener">{{ link }}</a> {{ successMsg }}
    </v-alert>
  </span>
</template>

<script>
export default {
  name: "Alerts",
  props: {
    success: { type: Boolean, default: false },
    error: { type: Boolean, default: false },
    successMsg: { type: String, default: null },
    errorMsg: { type: String, default: null },
    link: { type: String, default: null }
  }
};
</script>
